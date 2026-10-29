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

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Enterprise ingestion crosses three tables with foreign keys and CHECK
// constraints between them, so it can only be verified against a real database.
func TestOrgIntelIngestPopulatesTheWorkspace(t *testing.T) {
	dsn := os.Getenv("ASM_INTEGRATION_DB_DSN")
	if dsn == "" {
		t.Skip("ASM_INTEGRATION_DB_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.Ping())

	ctx := context.Background()
	const projectID = 2
	runID := seedOrgIntelRun(t, db, projectID)
	queries := dbgen.New(db)
	svc := NewService(NewRepository(queries), WithDB(db))

	raw := orgIntelCallbackPayload(t, runID)
	callback := DiscoveryCallback{
		TenantID: "tenant-org", OrgID: "org-org", ProjectID: projectID, RunID: runID, Seq: 1,
		SchemaVersion: callbackSchemaVersion, Phase: CallbackPhaseCompleted, Status: TaskRunStatusSuccess,
		PayloadHash: callbackPayloadHash(raw), Payload: raw, PayloadSize: uint32(len(raw)),
		IngestStatus: CallbackIngestProcessing,
	}
	require.NoError(t, svc.IngestCallbackFacts(ctx, callback))

	subjects, err := queries.ListProjectSubjects(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, subjects, 2, "the queried company and its subsidiary")

	// A collected subject is never primary and never verified: both are operator
	// decisions, and nothing here has been checked by a person.
	for _, subject := range subjects {
		assert.Equal(t, "unverified", subject.VerificationStatus,
			"collection must not be able to declare a subject verified")
		assert.False(t, subject.IsPrimary)
		assert.Equal(t, "org_intel", subject.Source)
	}

	filings, err := queries.ListICPFilings(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, filings, 1)
	assert.Equal(t, "京ICP备12345678号-1", filings[0].FilingNo)
	assert.Equal(t, "unverified", filings[0].Status)
	// The filing must hang off the subsidiary that holds it, not off the root.
	assert.Equal(t, subjects[1].ID, filings[0].SubjectID)

	// The ICP-proven domain became a real asset through the ordinary pipeline.
	var assetCount int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM asset WHERE project_id = ? AND value = 'example.com' AND asset_type = 'domain'`, projectID,
	).Scan(&assetCount))
	assert.Equal(t, 1, assetCount, "a domain proven by an ICP filing belongs in the inventory")

	// Rerunning the identical batch must converge, not accumulate.
	require.NoError(t, svc.IngestCallbackFacts(ctx, callback))
	subjectsAgain, err := queries.ListProjectSubjects(ctx, projectID)
	require.NoError(t, err)
	assert.Len(t, subjectsAgain, 2, "a repeated run must not duplicate subjects")
	filingsAgain, err := queries.ListICPFilings(ctx, projectID)
	require.NoError(t, err)
	assert.Len(t, filingsAgain, 1, "a repeated run must not duplicate filings")
}

// A subject an operator verified by hand must survive collection unchanged. If
// ingestion could reset it, one scheduled job would silently revoke the proof
// that gates active scanning.
func TestOrgIntelIngestDoesNotDowngradeAVerifiedSubject(t *testing.T) {
	dsn := os.Getenv("ASM_INTEGRATION_DB_DSN")
	if dsn == "" {
		t.Skip("ASM_INTEGRATION_DB_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()
	const projectID = 3
	runID := seedOrgIntelRun(t, db, projectID)
	queries := dbgen.New(db)
	svc := NewService(NewRepository(queries), WithDB(db))

	// An operator has already recorded and verified this company.
	_, err = db.ExecContext(ctx, `INSERT INTO project_subject
		(tenant_id,org_id,project_id,subject_key,subject_name,subject_type,is_primary,verification_status,source,created_by,updated_by)
		VALUES ('tenant-org','org-org',?,'code:91110108MA01ABCD2X','示例科技（北京）有限公司','company',TRUE,'verified','manual','alice','alice')`, projectID)
	require.NoError(t, err)

	raw := orgIntelCallbackPayload(t, runID)
	require.NoError(t, svc.IngestCallbackFacts(ctx, DiscoveryCallback{
		TenantID: "tenant-org", OrgID: "org-org", ProjectID: projectID, RunID: runID, Seq: 1,
		SchemaVersion: callbackSchemaVersion, Phase: CallbackPhaseCompleted, Status: TaskRunStatusSuccess,
		PayloadHash: callbackPayloadHash(raw), Payload: raw, PayloadSize: uint32(len(raw)),
		IngestStatus: CallbackIngestProcessing,
	}))

	subject, err := queries.GetProjectSubjectByKey(ctx, dbgen.GetProjectSubjectByKeyParams{
		ProjectID: projectID, SubjectKey: "code:91110108MA01ABCD2X",
	})
	require.NoError(t, err)
	assert.Equal(t, "verified", subject.VerificationStatus, "collection must not reset a verified subject")
	assert.True(t, subject.IsPrimary, "collection must not clear the primary flag")
	assert.Equal(t, "manual", subject.Source, "the operator's provenance must survive")
}

func seedOrgIntelRun(t *testing.T, db *sql.DB, projectID uint64) uint64 {
	t.Helper()
	ctx := context.Background()
	_, err := db.ExecContext(ctx, `INSERT IGNORE INTO project (id,tenant_id,org_id,project_code,name,owner,status,created_by,updated_by)
		VALUES (?,'tenant-org','org-org',CONCAT('org',?),'ORG','owner','active','seed','seed')`, projectID, projectID)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT IGNORE INTO scope (id,tenant_id,org_id,project_id,name,status,authorized_by,valid_from,valid_until,created_by,updated_by)
		VALUES (?,'tenant-org','org-org',?,'org','active','owner',UTC_TIMESTAMP(3),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 DAY),'seed','seed')`, projectID, projectID)
	require.NoError(t, err)
	// A company-typed scope target: the whole point of org_intel authorisation.
	_, err = db.ExecContext(ctx, `INSERT IGNORE INTO scope_target (id,tenant_id,org_id,project_id,scope_id,target_type,target_value,match_mode,created_by,updated_by)
		VALUES (?,'tenant-org','org-org',?,?,'company','示例集团','include','seed','seed')`, projectID, projectID, projectID)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT IGNORE INTO task_template (id,tenant_id,org_id,project_id,scope_id,name,task_type,config,enabled,timeout_seconds,rate_limit,concurrency,retry_limit,created_by,updated_by)
		VALUES (?,'tenant-org','org-org',?,?,'org','org_intel',JSON_OBJECT(),1,600,10,2,3,'seed','seed')`, projectID, projectID, projectID)
	require.NoError(t, err)
	result, err := db.ExecContext(ctx, `INSERT INTO task_run (tenant_id,org_id,project_id,template_id,scope_id,task_type,status,timeout_seconds,rate_limit,concurrency,retry_limit,engine_job_id,dispatched_at,started_at,created_by,updated_by)
		VALUES ('tenant-org','org-org',?,?,?,'org_intel','running',600,10,2,3,'job-org',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),'seed','seed')`, projectID, projectID, projectID)
	require.NoError(t, err)
	id, err := result.LastInsertId()
	require.NoError(t, err)
	require.Positive(t, id)
	return uint64(id) // #nosec G115 -- positive AUTO_INCREMENT checked above
}

func orgIntelCallbackPayload(t *testing.T, runID uint64) []byte {
	t.Helper()
	observed := time.Date(2026, time.July, 27, 3, 0, 0, 0, time.UTC)
	hash := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	rootOrg := map[string]any{
		"client_ref": "org-root", "natural_key": "org:示例集团", "name": "示例集团",
		"subject_type": "company", "source": "org_intel", "provider": "enscan",
		"observed_at": observed, "confidence": 90, "active_probe": false, "evidence_hash": hash,
	}
	childOrg := map[string]any{
		"client_ref": "org-child", "natural_key": "org:示例科技", "name": "示例科技（北京）有限公司",
		"subject_type": "company", "registration_code": "91110108MA01ABCD2X",
		"parent": map[string]any{"client_ref": "org-root"}, "equity_ratio": 100, "relation": "invest",
		"source": "org_intel", "provider": "enscan",
		"observed_at": observed, "confidence": 75, "active_probe": false, "evidence_hash": hash,
	}
	filing := map[string]any{
		"client_ref": "filing-1", "natural_key": "filing:京ICP备12345678号-1",
		"organization": map[string]any{"client_ref": "org-child"},
		"filing_no":    "京ICP备12345678号-1", "filing_type": "filing", "website_name": "示例官网",
		"domains": []any{"example.com"},
		"source":  "org_intel", "provider": "enscan",
		"observed_at": observed, "confidence": 85, "active_probe": false, "evidence_hash": hash,
	}
	domainAsset := map[string]any{
		"client_ref": "root-example", "natural_key": "domain:example.com",
		"asset_type": "domain", "value": "example.com",
		"source": "org_intel", "provider": "icp_filing",
		"observed_at": observed, "confidence": 90, "active_probe": false, "evidence_hash": hash,
	}

	raw, err := json.Marshal(map[string]any{
		"schema_version": callbackSchemaVersion, "run_id": runID, "seq": 1,
		"phase": CallbackPhaseCompleted, "status": TaskRunStatusSuccess,
		// assets + organizations + filings
		"result_count": 4,
		"observed_at":  observed,
		"assets":       []any{domainAsset}, "relations": []any{}, "exposures": []any{},
		"organizations": []any{rootOrg, childOrg}, "filings": []any{filing},
		"provider_errors": []any{}, "error_summary": "",
	})
	require.NoError(t, err)
	return raw
}
