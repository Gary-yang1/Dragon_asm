//go:build integration

package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// attributionCallback is shaped like a Baiyan DNS-stage batch: names resolving
// to addresses, where edge attributes are only present on some sightings.
func attributionCallback(t *testing.T, runID, seq uint64, observed time.Time, edgeTagged bool) []byte {
	t.Helper()
	meta := func(ref, naturalKey string) map[string]any {
		return map[string]any{
			"client_ref": ref, "natural_key": naturalKey, "source": "baiyan", "provider": "dns",
			"observed_at": observed, "confidence": 90, "active_probe": false,
			"evidence_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		}
	}
	var assets, relations []map[string]any
	edge := meta("ip-edge", "ip:104.16.1.1")
	edge["asset_type"], edge["value"] = "ip", "104.16.1.1"
	if edgeTagged {
		edge["attributes"] = map[string]string{
			"cdn_status": "identified", "cdn_provider": "Cloudflare", "ip_role": "cdn_edge",
			"cdn_evidence": "Address 104.16.1.1 is in CDN range 104.16.0.0/13", "attribution_rule_version": "cdn-rules-v2",
		}
	}
	origin := meta("ip-origin", "ip:198.51.100.7")
	origin["asset_type"], origin["value"] = "ip", "198.51.100.7"
	assets = append(assets, edge, origin)
	// Six names share the edge address; one name resolves to the origin. Six
	// more share 198.51.100.66, an address no rule identifies.
	shared := meta("ip-shared", "ip:198.51.100.66")
	shared["asset_type"], shared["value"] = "ip", "198.51.100.66"
	assets = append(assets, shared)
	for i := 0; i < 6; i++ {
		for _, target := range []struct{ prefix, ipRef string }{{"cdn", "ip-edge"}, {"vhost", "ip-shared"}} {
			name := fmt.Sprintf("%s%d.example.com", target.prefix, i)
			item := meta(name, "subdomain:"+name)
			item["asset_type"], item["value"] = "subdomain", name
			assets = append(assets, item)
			relation := meta("r-"+name, "relation:resolves:"+name)
			relation["relation_type"] = "resolves_to"
			relation["from"] = map[string]any{"client_ref": name}
			relation["to"] = map[string]any{"client_ref": target.ipRef}
			relations = append(relations, relation)
		}
	}
	own := meta("own.example.com", "subdomain:own.example.com")
	own["asset_type"], own["value"] = "subdomain", "own.example.com"
	assets = append(assets, own)
	ownRelation := meta("r-own", "relation:resolves:own")
	ownRelation["relation_type"] = "resolves_to"
	ownRelation["from"] = map[string]any{"client_ref": "own.example.com"}
	ownRelation["to"] = map[string]any{"client_ref": "ip-origin"}
	relations = append(relations, ownRelation)

	raw, err := json.Marshal(map[string]any{
		"schema_version": callbackSchemaVersion, "run_id": runID, "seq": seq,
		"phase": CallbackPhaseProgress, "status": TaskRunStatusRunning, "result_count": len(assets) + len(relations),
		"observed_at": observed, "assets": assets, "relations": relations,
		"exposures": []any{}, "provider_errors": []any{}, "error_summary": "",
	})
	require.NoError(t, err)
	return raw
}

func TestNetworkAttributionFromEngineFactsDrivesInventoryAndTargets(t *testing.T) {
	dsn := os.Getenv("ASM_NETWORK_ATTRIBUTION_TEST_DSN")
	if dsn == "" {
		t.Skip("ASM_NETWORK_ATTRIBUTION_TEST_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.Ping())

	ctx := context.Background()
	runID := seedIntegrationRun(t, db)
	queries := dbgen.New(db)
	svc := NewService(NewRepository(queries), WithDB(db))
	ingest := func(seq uint64, observed time.Time, tagged bool) {
		raw := attributionCallback(t, runID, seq, observed, tagged)
		require.NoError(t, svc.IngestCallbackFacts(ctx, DiscoveryCallback{
			TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, RunID: runID, Seq: seq,
			SchemaVersion: callbackSchemaVersion, Phase: CallbackPhaseProgress, Status: TaskRunStatusRunning,
			PayloadHash: callbackPayloadHash(raw), Payload: raw, PayloadSize: uint32(len(raw)), IngestStatus: CallbackIngestProcessing,
		}))
	}
	first := time.Date(2026, time.October, 30, 1, 0, 0, 0, time.UTC)
	ingest(1, first, true)
	// A later sighting that cannot tell must not erase the identification.
	ingest(2, first.Add(time.Hour), false)

	var role, provider, version string
	var sourceRun uint64
	require.NoError(t, db.QueryRowContext(ctx, `SELECT n.role,n.provider,n.rule_version,n.source_run_id FROM asset_network_attribution n
		JOIN asset a ON a.id=n.asset_id WHERE a.project_id=1 AND a.value='104.16.1.1'`).Scan(&role, &provider, &version, &sourceRun))
	require.Equal(t, AttributionCDNEdge, role)
	require.Equal(t, "Cloudflare", provider)
	require.Equal(t, "cdn-rules-v2", version)
	require.Equal(t, runID, sourceRun)
	require.Equal(t, int64(1), scalarCount(t, db, "SELECT COUNT(*) FROM asset_network_attribution WHERE project_id=1"),
		"only the identified address is stored; unknown is not recorded as a negative")

	assets := asset.NewService(asset.NewRepository(queries), asset.WithDB(db))
	summary, err := assets.Summary(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, int64(2), summary.ByType.IP, "the edge address is not the organisation's IP")
	require.Equal(t, int64(1), summary.Network.CDNEdge)
	require.Equal(t, int64(1), summary.Network.SharedIP, "198.51.100.66 is resolved by six names and not an identified edge")

	list := func(category string) []string {
		rows, _, err := assets.ListFiltered(ctx, asset.ListFilter{ProjectID: 1, Category: category, Limit: 50})
		require.NoError(t, err)
		var values []string
		for _, row := range rows {
			values = append(values, row.Value)
		}
		return values
	}
	require.ElementsMatch(t, []string{"198.51.100.7", "198.51.100.66"}, list(asset.CategoryIPs))
	require.ElementsMatch(t, []string{"104.16.1.1"}, list(asset.CategoryCDNEdges))

	var ids []uint64
	for _, value := range []string{"104.16.1.1", "198.51.100.66", "198.51.100.7"} {
		var id uint64
		require.NoError(t, db.QueryRowContext(ctx, "SELECT id FROM asset WHERE project_id=1 AND value=?", value).Scan(&id))
		ids = append(ids, id)
	}
	info, err := assets.NetworkInfo(ctx, 1, ids)
	require.NoError(t, err)
	require.Len(t, info, 3)
	byID := map[uint64]asset.NetworkInfo{}
	for _, item := range info {
		byID[item.AssetID] = item
	}
	require.Equal(t, AttributionCDNEdge, byID[ids[0]].Role)
	require.Equal(t, int64(6), byID[ids[0]].ResolvedBy)
	require.False(t, byID[ids[0]].Shared, "an identified edge is reported as an edge, not as shared")
	require.True(t, byID[ids[1]].Shared)
	require.False(t, byID[ids[2]].Shared)

	repo := NewRepository(queries)
	rows, err := repo.ListIPNetworkAttribution(ctx, 1, []string{"104.16.1.1", "198.51.100.66", "203.0.113.200"})
	require.NoError(t, err)
	require.Len(t, rows, 2, "a value with no IP asset is absent")
	require.NoError(t, svc.refuseCDNEdgeTargets(ctx, 1, TaskTypePortProbe, []DispatchTarget{{Type: TargetTypeIP, Value: "198.51.100.7"}}))
	require.ErrorIs(t, svc.refuseCDNEdgeTargets(ctx, 1, TaskTypePortProbe, []DispatchTarget{{Type: TargetTypeIP, Value: "104.16.1.1"}}), ErrActiveTargetCDNEdge)
}
