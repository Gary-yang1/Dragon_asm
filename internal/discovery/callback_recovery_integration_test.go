//go:build integration

package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

func openCallbackRecoveryDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("ASM_CALLBACK_CONCURRENCY_TEST_DSN")
	if dsn == "" {
		t.Skip("ASM_CALLBACK_CONCURRENCY_TEST_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(40)
	require.NoError(t, db.Ping())
	return db
}

// sharedAddressCallback is one DNS batch: twenty names that all resolve to the
// same three edge addresses, as a passive job against a CDN-fronted domain does.
func sharedAddressCallback(t *testing.T, runID, seq uint64) []byte {
	t.Helper()
	observed := time.Date(2026, time.October, 30, 2, 0, 0, 0, time.UTC)
	meta := func(ref, naturalKey string) map[string]any {
		return map[string]any{
			"client_ref": ref, "natural_key": naturalKey, "source": "baiyan", "provider": "dns",
			"observed_at": observed, "confidence": 90, "active_probe": false,
			"evidence_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		}
	}
	var assets, relations []map[string]any
	for i := 1; i <= 3; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		item := meta("ip-"+ip, "ip:"+ip)
		item["asset_type"], item["value"] = "ip", ip
		assets = append(assets, item)
	}
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("h%d-%d.example.com", seq, i)
		item := meta(name, "subdomain:"+name)
		item["asset_type"], item["value"] = "subdomain", name
		assets = append(assets, item)
		for j := 1; j <= 3; j++ {
			ip := fmt.Sprintf("198.51.100.%d", j)
			relation := meta(fmt.Sprintf("r-%s-%d", name, j), fmt.Sprintf("relation:resolves:%s:%d", name, j))
			relation["relation_type"] = "resolves_to"
			relation["from"] = map[string]any{"client_ref": name}
			relation["to"] = map[string]any{"client_ref": "ip-" + ip}
			relations = append(relations, relation)
		}
	}
	raw, err := json.Marshal(map[string]any{
		"schema_version": callbackSchemaVersion, "run_id": runID, "seq": seq,
		"phase": CallbackPhaseProgress, "status": TaskRunStatusRunning, "result_count": len(assets) + len(relations),
		"observed_at": observed, "assets": assets, "relations": relations,
		"exposures": []any{}, "provider_errors": []any{}, "error_summary": "",
	})
	require.NoError(t, err)
	return raw
}

// Run 22 on the test environment: concurrent ingests of one run's callbacks
// deadlocked on the shared addresses' asset and relation rows, and some ran out
// of lock-conflict retries. Ingests of one run now queue on the run lock.
func TestConcurrentIngestOfCallbacksSharingAddressesDoesNotFail(t *testing.T) {
	db := openCallbackRecoveryDB(t)
	defer db.Close()
	ctx := context.Background()
	runID := seedIntegrationRun(t, db)
	svc := NewService(NewRepository(dbgen.New(db)), WithDB(db))

	const callbacks = 30
	start := make(chan struct{})
	errs := make(chan error, callbacks)
	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	for seq := uint64(1); seq <= callbacks; seq++ {
		raw := sharedAddressCallback(t, runID, seq)
		callback := DiscoveryCallback{
			TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, RunID: runID, Seq: seq,
			SchemaVersion: callbackSchemaVersion, Phase: CallbackPhaseProgress, Status: TaskRunStatusRunning,
			PayloadHash: callbackPayloadHash(raw), Payload: raw, PayloadSize: uint32(len(raw)), IngestStatus: CallbackIngestProcessing,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			sem <- struct{}{}
			defer func() { <-sem }()
			errs <- svc.IngestCallbackFacts(ctx, callback)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int64(3), scalarCount(t, db, "SELECT COUNT(*) FROM asset WHERE project_id=1 AND asset_type='ip' AND deleted_at='1970-01-01 00:00:00.000'"))
	require.Equal(t, int64(callbacks*20), scalarCount(t, db, "SELECT COUNT(*) FROM asset WHERE project_id=1 AND asset_type='subdomain' AND deleted_at='1970-01-01 00:00:00.000'"))
	require.Equal(t, int64(callbacks*20*3), scalarCount(t, db, "SELECT COUNT(*) FROM asset_relation WHERE project_id=1 AND relation_type='resolves_to' AND deleted_at='1970-01-01 00:00:00.000'"))
}

// A claim abandoned in processing used to stay unclaimable for five minutes
// after recovery re-enqueued it, because the enqueue mark touched updated_at.
func TestRecoveryReleasesAbandonedClaimForImmediateRetry(t *testing.T) {
	db := openCallbackRecoveryDB(t)
	defer db.Close()
	ctx := context.Background()
	runID := seedIntegrationRun(t, db)
	repo := NewRepository(dbgen.New(db))
	enqueuer := &fakeCallbackEnqueuer{}
	svc := NewService(repo, WithDB(db))
	svc.callbackEnqueuer = enqueuer

	raw := []byte(`{}`)
	inserted, err := repo.InsertDiscoveryCallback(ctx, DiscoveryCallback{
		TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, RunID: runID, Seq: 1,
		SchemaVersion: callbackSchemaVersion, Phase: CallbackPhaseProgress, Status: TaskRunStatusRunning,
		ObservedAt: time.Now().UTC(), PayloadHash: callbackPayloadHash(raw), Payload: raw, PayloadSize: uint32(len(raw)),
		ReceivedAt: time.Now().UTC(), IngestStatus: CallbackIngestProcessing,
	})
	require.NoError(t, err)
	require.True(t, inserted)
	// A worker claimed it ten minutes ago and never finished.
	_, err = db.ExecContext(ctx, `UPDATE discovery_callback SET ingest_attempt=1, updated_at=DATE_SUB(CURRENT_TIMESTAMP(3), INTERVAL 10 MINUTE) WHERE run_id=? AND seq=1`, runID)
	require.NoError(t, err)

	recovered, err := svc.RecoverPendingCallbacks(ctx, 100)
	require.NoError(t, err)
	require.Equal(t, 1, recovered)

	claimed, err := svc.ClaimDiscoveryCallbackIngest(ctx, 1, runID, 1)
	require.NoError(t, err)
	require.True(t, claimed, "the re-enqueued callback must be claimable now, not five minutes after recovery")
	var attempt int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT ingest_attempt FROM discovery_callback WHERE run_id=? AND seq=1", runID).Scan(&attempt))
	require.Equal(t, 2, attempt)

	// A fresh claim is not stale and is left alone.
	recovered, err = svc.RecoverPendingCallbacks(ctx, 100)
	require.NoError(t, err)
	require.Equal(t, 0, recovered)
}
