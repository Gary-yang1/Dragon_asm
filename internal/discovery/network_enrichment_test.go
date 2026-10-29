package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

func TestNetworkInputNormalizesAndRejectsInvalidNeighbors(t *testing.T) {
	for _, test := range []struct{ url, host string }{{"https://EXAMPLE.COM./", "example.com"}, {"http://[2001:0db8::1]/", "2001:db8::1"}, {"http://localhost/", ""}, {"http://service.local/", ""}, {"http://169.254.169.254/", ""}} {
		raw, _ := json.Marshal(map[string]string{"url": test.url, "fingerprint": "nginx\x1b, CloudFront"})
		item, err := networkInput(enrichmentWork{ID: 1, Raw: raw})
		if test.host == "" {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, test.host, item.Host)
		require.Equal(t, []string{"CloudFront"}, item.Fingerprints)
	}
}

func TestNetworkEnrichmentClientCorrelation(t *testing.T) {
	for _, test := range []struct {
		name, key, host, status string
		valid                   bool
	}{{"valid", "1", "example.test", "success", true}, {"wrong key", "2", "example.test", "success", false}, {"wrong host", "1", "other.test", "success", false}, {"invalid status", "1", "example.test", "invented", false}} {
		t.Run(test.name, func(t *testing.T) {
			a, err := NewHTTPEngineAdapter("https://baiyan.example", "test", fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
				require.Equal(t, "/enrich/network", req.URL.Path)
				b, _ := json.Marshal(map[string]any{"schema_version": "1.0", "items": []any{map[string]any{"key": test.key, "host": test.host, "status": test.status, "resolved_ips": []string{"192.0.2.1"}, "cname_chain": []string{}, "cdn": map[string]string{"status": "unknown"}, "cloud": map[string]string{"status": "unknown"}, "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "rule_version": "dns-cname-v1"}}})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
			}})
			require.NoError(t, err)
			_, err = a.enrichNetwork(context.Background(), []networkEnrichmentInput{{Key: "1", Host: "example.test"}})
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// A disposable database exercises source selection, leases and retry fencing.
func TestNetworkEnrichmentMySQLLifecycle(t *testing.T) {
	dsn := os.Getenv("ASM_NETWORK_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated database not configured")
	}
	cfg, err := mysql.ParseDSN(dsn)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(cfg.DBName, "asm_network_test_"))
	cfg.MultiStatements = true
	cfg.ParseTime = true
	db, err := sql.Open("mysql", cfg.FormatDSN())
	require.NoError(t, err)
	defer db.Close()
	files, err := filepath.Glob("../../migrations/*.up.sql")
	require.NoError(t, err)
	for _, file := range files {
		body, err := os.ReadFile(file)
		require.NoError(t, err)
		_, err = db.Exec(string(body))
		require.NoError(t, err, filepath.Base(file))
	}
	runID := seedEngineSettingsTestRun(t, db)
	_, err = db.Exec(`UPDATE task_run SET task_type='web_probe',status='success' WHERE id=?`, runID)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO engine_run_settings(project_id,run_id,version) SELECT 1,?,version FROM engine_settings_version LIMIT 1`, runID)
	require.NoError(t, err)
	insert := func(id uint64, host string) {
		raw, _ := json.Marshal(map[string]any{"url": "https://" + host, "exposure_type": "web", "fingerprint": "CloudFront"})
		_, err := db.Exec(`INSERT INTO discovery_observation(id,tenant_id,org_id,project_id,run_id,seq,kind,natural_key,provider,capability,observed_at,evidence_hash,normalized_json,normalized_size,ingest_status) VALUES (?,'tenant-e2e','org-e2e',1,?,1,'exposure',?,'active','web_probe',UTC_TIMESTAMP(3),REPEAT('a',64),?,?,'materialized')`, id, runID, host, string(raw), len(raw))
		require.NoError(t, err)
	}
	insert(1, "one.example.test")
	insert(2, "two.example.test")
	svc := NewService(NewRepository(dbgen.New(db)), WithDB(db))
	ctx := context.Background()
	require.NoError(t, svc.seedNetworkEnrichment(ctx))
	require.NoError(t, svc.seedNetworkEnrichment(ctx))
	var total int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM web_network_enrichment`).Scan(&total))
	require.Equal(t, 2, total)
	var wg sync.WaitGroup
	claims := make(chan []enrichmentWork, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, e := svc.claimNetworkEnrichment(ctx)
			if e != nil {
				t.Error(e)
			}
			claims <- rows
		}()
	}
	wg.Wait()
	close(claims)
	all := []enrichmentWork{}
	for c := range claims {
		all = append(all, c...)
	}
	require.Len(t, all, 2)
	require.NotEqual(t, all[0].ID, all[1].ID)
	first := all[0]
	require.NoError(t, svc.finishNetworkEnrichment(ctx, first, &networkEnrichmentResult{Key: strconvForTest(first.ID), Host: "one.example.test", Status: "success", ObservedAt: time.Now()}, "", false))
	var state string
	require.NoError(t, db.QueryRow(`SELECT state FROM web_network_enrichment WHERE observation_id=?`, first.ID).Scan(&state))
	require.Equal(t, "complete", state)
	second := all[1]
	_, err = db.Exec(`UPDATE web_network_enrichment SET lease_until=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 SECOND) WHERE observation_id=?`, second.ID)
	require.NoError(t, err)
	reclaimed, err := svc.claimNetworkEnrichment(ctx)
	require.NoError(t, err)
	require.Len(t, reclaimed, 1)
	require.NotEqual(t, second.Token, reclaimed[0].Token)
	require.NoError(t, svc.finishNetworkEnrichment(ctx, second, nil, "stale", true))
	require.NoError(t, db.QueryRow(`SELECT state FROM web_network_enrichment WHERE observation_id=?`, second.ID).Scan(&state))
	require.Equal(t, "running", state)
	_, err = db.Exec(`UPDATE discovery_observation SET normalized_json=JSON_SET(normalized_json,'$.url','https://changed.example.test') WHERE id=?`, second.ID)
	require.NoError(t, err)
	require.NoError(t, svc.finishNetworkEnrichment(ctx, reclaimed[0], nil, "", false))
	require.NoError(t, db.QueryRow(`SELECT state FROM web_network_enrichment WHERE observation_id=?`, second.ID).Scan(&state))
	require.Equal(t, "failed", state)
	require.NoError(t, db.QueryRow(`SELECT status FROM task_run WHERE id=?`, runID).Scan(&state))
	require.Equal(t, "success", state)
	n, err := svc.RetryNetworkEnrichment(ctx, 1, runID, "test", AuditMeta{})
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	work, err := svc.claimNetworkEnrichment(ctx)
	require.NoError(t, err)
	require.Len(t, work, 1)
	w := work[0]
	w.Attempts = 5
	require.NoError(t, svc.finishNetworkEnrichment(ctx, w, nil, "DNS failed", false))
	require.NoError(t, db.QueryRow(`SELECT state FROM web_network_enrichment WHERE observation_id=?`, w.ID).Scan(&state))
	require.Equal(t, "failed", state)
	_, err = svc.RetryNetworkEnrichment(ctx, 999, runID, "test", AuditMeta{})
	require.Error(t, err)
}

func strconvForTest(v uint64) string { raw, _ := json.Marshal(v); return string(raw) }
