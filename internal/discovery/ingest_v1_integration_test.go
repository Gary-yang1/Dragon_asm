//go:build integration

package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

func TestV1IngestGraphIdempotencyAndRollback(t *testing.T) {
	dsn := os.Getenv("ASM_INTEGRATION_DB_DSN")
	if dsn == "" {
		t.Skip("ASM_INTEGRATION_DB_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.Ping())

	ctx := context.Background()
	runID := seedIntegrationRun(t, db)
	queries := dbgen.New(db)
	assetSvc := asset.NewService(asset.NewRepository(queries))
	manual, err := assetSvc.Import(ctx, asset.ImportInput{
		TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1,
		AssetType: asset.TypeSubdomain, Value: "api.example.com", Source: "manual",
		Confidence: 100, Status: asset.StatusActive, ActorID: "seed",
	})
	require.NoError(t, err)

	raw := integrationGraphCallback(t, runID, 1, false)
	callback := DiscoveryCallback{
		TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, RunID: runID, Seq: 1,
		SchemaVersion: callbackSchemaVersion, Phase: CallbackPhaseProgress, Status: TaskRunStatusRunning,
		PayloadHash: callbackPayloadHash(raw), Payload: raw, PayloadSize: uint32(len(raw)), IngestStatus: CallbackIngestProcessing,
	}
	svc := NewService(NewRepository(queries), WithDB(db))
	require.NoError(t, svc.IngestCallbackFacts(ctx, callback))

	assert.Equal(t, int64(3), scalarCount(t, db, "SELECT COUNT(*) FROM asset WHERE project_id=1 AND deleted_at='1970-01-01 00:00:00.000'"))
	assert.Equal(t, int64(2), scalarCount(t, db, "SELECT COUNT(*) FROM asset_relation WHERE project_id=1 AND deleted_at='1970-01-01 00:00:00.000'"))
	assert.Equal(t, int64(6), scalarCount(t, db, "SELECT COUNT(*) FROM discovery_observation WHERE project_id=1 AND run_id=?", runID))
	var source string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT source FROM asset WHERE id=? AND project_id=1", manual.ID).Scan(&source))
	assert.Equal(t, "manual", source, "discovery must not overwrite a manual primary source")
	firstEvents := scalarCount(t, db, "SELECT COUNT(*) FROM change_event WHERE project_id=1")
	require.Positive(t, firstEvents)

	require.NoError(t, svc.IngestCallbackFacts(ctx, callback))
	assert.Equal(t, int64(3), scalarCount(t, db, "SELECT COUNT(*) FROM asset WHERE project_id=1 AND deleted_at='1970-01-01 00:00:00.000'"))
	assert.Equal(t, int64(2), scalarCount(t, db, "SELECT COUNT(*) FROM asset_relation WHERE project_id=1 AND deleted_at='1970-01-01 00:00:00.000'"))
	assert.Equal(t, int64(6), scalarCount(t, db, "SELECT COUNT(*) FROM discovery_observation WHERE project_id=1 AND run_id=?", runID))
	assert.Equal(t, firstEvents, scalarCount(t, db, "SELECT COUNT(*) FROM change_event WHERE project_id=1"), "unchanged retry must not duplicate events")

	rollbackRaw := integrationGraphCallback(t, runID, 2, true)
	rollbackCallback := callback
	rollbackCallback.Seq = 2
	rollbackCallback.Payload = rollbackRaw
	rollbackCallback.PayloadHash = callbackPayloadHash(rollbackRaw)
	rollbackCallback.PayloadSize = uint32(len(rollbackRaw))
	err = svc.IngestCallbackFacts(ctx, rollbackCallback)
	assert.ErrorIs(t, err, ErrCallbackFactReference)
	assert.Equal(t, int64(0), scalarCount(t, db, "SELECT COUNT(*) FROM asset WHERE project_id=1 AND asset_key='subdomain:rollback.example.com'"))
	assert.Equal(t, int64(0), scalarCount(t, db, "SELECT COUNT(*) FROM discovery_observation WHERE project_id=1 AND run_id=? AND seq=2", runID))

	// A successful completed run applies lifecycle only to assets governed by
	// this capability. The discovery IP misses and becomes inactive at threshold
	// one; the manually sourced subdomain is never penalized.
	lifecycleRunID := seedAdditionalIntegrationRun(t, db)
	finalRaw := integrationFinalRootCallback(t, lifecycleRunID)
	finalCallback := DiscoveryCallback{
		TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, RunID: lifecycleRunID, Seq: 1,
		SchemaVersion: callbackSchemaVersion, Phase: CallbackPhaseCompleted, Status: TaskRunStatusSuccess,
		ObservedAt: time.Date(2026, time.July, 13, 3, 0, 0, 0, time.UTC), PayloadHash: callbackPayloadHash(finalRaw),
		Payload: finalRaw, PayloadSize: uint32(len(finalRaw)), ResultCount: 1,
		ReceivedAt: time.Now().UTC(), IngestStatus: CallbackIngestProcessing,
	}
	inserted, err := NewRepository(queries).InsertDiscoveryCallback(ctx, finalCallback)
	require.NoError(t, err)
	require.True(t, inserted)
	lifecycleSvc := NewService(NewRepository(queries), WithDB(db), WithAssetMissThreshold(1))
	require.NoError(t, lifecycleSvc.IngestCallbackFacts(ctx, finalCallback))
	completed, err := lifecycleSvc.CompleteDiscoveryCallbackIngest(ctx, 1, lifecycleRunID, 1)
	require.NoError(t, err)
	assert.True(t, completed.Finalized)
	var runStatus string
	require.NoError(t, db.QueryRow("SELECT status FROM task_run WHERE id=? AND project_id=1", lifecycleRunID).Scan(&runStatus))
	assert.Equal(t, TaskRunStatusSuccess, runStatus)
	var ipStatus, manualStatus string
	require.NoError(t, db.QueryRow("SELECT status FROM asset WHERE project_id=1 AND asset_key='ip:192.0.2.10'").Scan(&ipStatus))
	require.NoError(t, db.QueryRow("SELECT status FROM asset WHERE project_id=1 AND asset_key='subdomain:api.example.com'").Scan(&manualStatus))
	assert.Equal(t, asset.StatusInactive, ipStatus)
	assert.Equal(t, asset.StatusActive, manualStatus)
}

func seedIntegrationRun(t *testing.T, db *sql.DB) uint64 {
	t.Helper()
	ctx := context.Background()
	_, err := db.ExecContext(ctx, `INSERT INTO project (id,tenant_id,org_id,project_code,name,owner,status,created_by,updated_by)
		VALUES (1,'tenant-e2e','org-e2e','ext06','EXT06','owner','active','seed','seed')`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO scope (id,tenant_id,org_id,project_id,name,status,authorized_by,valid_from,valid_until,created_by,updated_by)
		VALUES (1,'tenant-e2e','org-e2e',1,'ext06','active','owner',UTC_TIMESTAMP(3),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 DAY),'seed','seed')`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO task_template (id,tenant_id,org_id,project_id,scope_id,name,task_type,config,enabled,timeout_seconds,rate_limit,concurrency,retry_limit,created_by,updated_by)
		VALUES (1,'tenant-e2e','org-e2e',1,1,'ext06','passive_intel',JSON_OBJECT(),1,60,10,2,3,'seed','seed')`)
	require.NoError(t, err)
	result, err := db.ExecContext(ctx, `INSERT INTO task_run (tenant_id,org_id,project_id,template_id,scope_id,task_type,status,timeout_seconds,rate_limit,concurrency,retry_limit,engine_job_id,dispatched_at,started_at,created_by,updated_by)
		VALUES ('tenant-e2e','org-e2e',1,1,1,'passive_intel','running',60,10,2,3,'job-ext06',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),'seed','seed')`)
	require.NoError(t, err)
	id, err := result.LastInsertId()
	require.NoError(t, err)
	require.Positive(t, id)
	return uint64(id) // #nosec G115 -- positive AUTO_INCREMENT checked above
}

func seedAdditionalIntegrationRun(t *testing.T, db *sql.DB) uint64 {
	t.Helper()
	result, err := db.Exec(`INSERT INTO task_run (tenant_id,org_id,project_id,template_id,scope_id,task_type,status,timeout_seconds,rate_limit,concurrency,retry_limit,engine_job_id,dispatched_at,started_at,created_by,updated_by)
		VALUES ('tenant-e2e','org-e2e',1,1,1,'passive_intel','running',60,10,2,3,'job-lifecycle',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),'seed','seed')`)
	require.NoError(t, err)
	id, err := result.LastInsertId()
	require.NoError(t, err)
	require.Positive(t, id)
	return uint64(id) // #nosec G115 -- positive AUTO_INCREMENT checked above
}

func integrationFinalRootCallback(t *testing.T, runID uint64) []byte {
	t.Helper()
	observed := time.Date(2026, time.July, 13, 3, 0, 0, 0, time.UTC)
	assetFact := map[string]any{
		"client_ref": "root-final", "natural_key": "domain:example.com", "asset_type": "domain", "value": "example.com",
		"source": "baiyan", "provider": "mock-ct", "observed_at": observed, "confidence": 90,
		"active_probe": false, "evidence_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	raw, err := json.Marshal(map[string]any{
		"schema_version": callbackSchemaVersion, "run_id": runID, "seq": 1,
		"phase": CallbackPhaseCompleted, "status": TaskRunStatusSuccess, "result_count": 1,
		"observed_at": observed, "assets": []any{assetFact}, "relations": []any{},
		"exposures": []any{}, "provider_errors": []any{}, "error_summary": "",
	})
	require.NoError(t, err)
	return raw
}

func integrationGraphCallback(t *testing.T, runID, seq uint64, rollback bool) []byte {
	t.Helper()
	observed := time.Date(2026, time.July, 13, 2, 0, 0, 0, time.UTC)
	evidence := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	meta := func(ref, naturalKey, provider string) map[string]any {
		return map[string]any{
			"client_ref": ref, "natural_key": naturalKey, "source": "baiyan", "provider": provider,
			"observed_at": observed, "confidence": 90, "active_probe": false, "evidence_hash": evidence,
		}
	}
	assets := []map[string]any{}
	relations := []map[string]any{}
	if rollback {
		item := meta("rollback", "subdomain:rollback.example.com", "mock")
		item["asset_type"], item["value"] = "subdomain", "rollback.example.com"
		assets = append(assets, item)
		relation := meta("bad-relation", "relation:bad", "mock")
		relation["relation_type"] = "resolves_to"
		relation["from"] = map[string]any{"client_ref": "rollback"}
		relation["to"] = map[string]any{"client_ref": "missing"}
		relations = append(relations, relation)
	} else {
		for _, definition := range []struct{ ref, natural, provider, kind, value string }{
			{"root", "domain:example.com", "mock-ct", "domain", "example.com"},
			{"sub-ct", "subdomain:api.example.com", "mock-ct", "subdomain", "api.example.com"},
			{"sub-dns", "subdomain:api.example.com", "mock-dns", "subdomain", "api.example.com"},
			{"ip", "ip:192.0.2.10", "mock-dns", "ip", "192.0.2.10"},
		} {
			item := meta(definition.ref, definition.natural, definition.provider)
			item["asset_type"], item["value"] = definition.kind, definition.value
			assets = append(assets, item)
		}
		for _, definition := range []struct{ ref, natural, relationType, from, to string }{
			{"contains", "relation:contains:root:sub", "contains", "root", "sub-ct"},
			{"resolves", "relation:resolves:sub:ip", "resolves_to", "sub-dns", "ip"},
		} {
			relation := meta(definition.ref, definition.natural, "mock-dns")
			relation["relation_type"] = definition.relationType
			relation["from"] = map[string]any{"client_ref": definition.from}
			relation["to"] = map[string]any{"client_ref": definition.to}
			relations = append(relations, relation)
		}
	}
	resultCount := len(assets) + len(relations)
	raw, err := json.Marshal(map[string]any{
		"schema_version": callbackSchemaVersion, "run_id": runID, "seq": seq,
		"phase": CallbackPhaseProgress, "status": TaskRunStatusRunning, "result_count": resultCount,
		"observed_at": observed, "assets": assets, "relations": relations,
		"exposures": []any{}, "provider_errors": []any{}, "error_summary": "",
	})
	require.NoError(t, err)
	return raw
}

func scalarCount(t *testing.T, db *sql.DB, query string, args ...any) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.QueryRow(query, args...).Scan(&count))
	return count
}
