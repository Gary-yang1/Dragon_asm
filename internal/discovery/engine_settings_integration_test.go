package discovery

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Runs only against a dedicated disposable database, never the application's database.
func TestEngineSettingsMySQLLifecycle(t *testing.T) {
	raw := os.Getenv("ASM_ENGINE_SETTINGS_TEST_DSN")
	if raw == "" {
		t.Skip("dedicated engine settings test database not configured")
	}
	cfg, err := mysql.ParseDSN(raw)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(cfg.DBName, "asm_engine_settings_test_"))
	cfg.MultiStatements = true
	cfg.ParseTime = true
	db, err := sql.Open("mysql", cfg.FormatDSN())
	require.NoError(t, err)
	defer db.Close()
	migrations, err := filepath.Glob("../../migrations/*.up.sql")
	require.NoError(t, err)
	for _, path := range migrations {
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		_, err = db.Exec(string(body))
		require.NoError(t, err, filepath.Base(path))
	}
	ctx := context.Background()
	store, err := NewEngineSettingsStore(db, bytes.Repeat([]byte{9}, 32))
	require.NoError(t, err)
	original := settingsFixture()
	require.NoError(t, store.Bootstrap(ctx, original))
	require.NoError(t, store.Bootstrap(ctx, EngineSettings{}))
	current, err := store.Latest(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), current.Version)
	require.Equal(t, original.PassiveToken, current.Settings.PassiveToken)
	seedEngineSettingsTestRun(t, db)
	svc := NewService(NewRepository(dbgen.New(db)), WithDB(db), WithEngineSettings(store))
	first, err := svc.CreateTaskRun(ctx, CreateTaskRunInput{ProjectID: 1, TemplateID: 1, ActorID: "1"})
	require.NoError(t, err)
	next := original
	next.PassiveURL = "https://new.example.test"
	next.PassiveToken = "next-private-token"
	event := audit.Event{TenantID: "tenant-e2e", OrgID: "org-e2e", ActorID: "1", ActorType: audit.ActorUser, Action: "platform.discovery_engine.configuration.update", ResourceType: ResourceTypeEngine, ResourceID: "configuration"}
	_, err = store.Save(ctx, 1, next, event)
	require.NoError(t, err)
	second, err := svc.CreateTaskRun(ctx, CreateTaskRunInput{ProjectID: 1, TemplateID: 1, ActorID: "1"})
	require.NoError(t, err)
	pinned, err := store.ForRun(ctx, 1, first.ID)
	require.NoError(t, err)
	require.Equal(t, uint64(1), pinned.Version)
	pinned, err = store.ForRun(ctx, 1, second.ID)
	require.NoError(t, err)
	require.Equal(t, uint64(2), pinned.Version)
	// Two edits from the same form revision cannot both commit.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := store.Save(ctx, 2, next, event); results <- err }()
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, ErrEngineSettingsConflict)
			conflicts++
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, conflicts)
	reopened, err := NewEngineSettingsStore(db, bytes.Repeat([]byte{9}, 32))
	require.NoError(t, err)
	latest, err := reopened.Latest(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(3), latest.Version)
	var payload []byte
	require.NoError(t, db.QueryRow("SELECT encrypted_payload FROM engine_settings_version WHERE version=1").Scan(&payload))
	require.NotContains(t, string(payload), original.PassiveToken)
	rows, err := db.Query("SELECT COALESCE(before_json,''), COALESCE(after_json,''), COALESCE(metadata_json,'') FROM audit_log")
	require.NoError(t, err)
	for rows.Next() {
		var before, after, meta string
		require.NoError(t, rows.Scan(&before, &after, &meta))
		require.NotContains(t, before+after+meta, original.PassiveToken)
		require.NotContains(t, before+after+meta, next.PassiveToken)
	}
	require.NoError(t, rows.Close())
	// Schema rollback/reapply is tested only in this disposable database.
	down, err := os.ReadFile("../../migrations/000031_engine_settings.down.sql")
	require.NoError(t, err)
	_, err = db.Exec(string(down))
	require.NoError(t, err)
	up, err := os.ReadFile("../../migrations/000031_engine_settings.up.sql")
	require.NoError(t, err)
	_, err = db.Exec(string(up))
	require.NoError(t, err)
	require.NoError(t, store.Bootstrap(ctx, original))
}

func seedEngineSettingsTestRun(t *testing.T, db *sql.DB) uint64 {
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
