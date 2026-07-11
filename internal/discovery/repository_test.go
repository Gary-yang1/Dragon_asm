package discovery

import (
	"context"
	"database/sql"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var (
	scopeCols        = []string{"id", "tenant_id", "org_id", "project_id", "name", "status", "authorized_by", "valid_from", "valid_until", "created_at", "updated_at", "created_by", "updated_by", "deleted_at"}
	scopeTargetCols  = []string{"id", "tenant_id", "org_id", "project_id", "scope_id", "target_type", "match_mode", "target_value", "created_at", "updated_at", "created_by", "updated_by", "deleted_at"}
	taskTemplateCols = []string{
		"id", "tenant_id", "org_id", "project_id", "scope_id", "name", "task_type", "config", "schedule", "enabled",
		"timeout_seconds", "rate_limit", "concurrency", "retry_limit", "created_at", "updated_at", "created_by", "updated_by", "deleted_at",
	}
	taskRunCols = []string{
		"id", "tenant_id", "org_id", "project_id", "template_id", "scope_id", "task_type", "status", "progress", "timeout_seconds", "rate_limit", "concurrency", "retry_limit",
		"attempt", "engine_job_id", "dispatched_at", "last_callback_at", "result_count", "callback_secret_ref",
		"started_at", "finished_at", "error_summary", "created_at", "updated_at", "created_by", "updated_by", "deleted_at",
	}
)

// softDeleteFilter mirrors the query predicate for all live-row reads.
const softDeleteFilter = "deleted_at = '1970-01-01 00:00:00.000'"

func scopeRows(now time.Time, id, projectID uint64, name string) *sqlmock.Rows {
	return sqlmock.NewRows(scopeCols).AddRow(
		id, "t1", "o1", projectID, name, StatusActive, "owner-ok",
		now.Add(-time.Hour), now.Add(time.Hour),
		now, now, "u1", "u1", time.Time{},
	)
}

func scopeTargetRows(now time.Time, scopeID, projectID uint64, targetType, matchMode, targetValue string) *sqlmock.Rows {
	return sqlmock.NewRows(scopeTargetCols).AddRow(
		uint64(10), "t1", "o1", projectID, scopeID,
		targetType, matchMode, targetValue,
		now, now, "u1", "u1", time.Time{},
	)
}

func taskTemplateRows(now time.Time, templateID, projectID, scopeID uint64, name, taskType string, enabled bool) *sqlmock.Rows {
	return sqlmock.NewRows(taskTemplateCols).AddRow(
		templateID, "t1", "o1", projectID, scopeID,
		name, taskType, []byte(`{"target":"example.com"}`), "* * * * *", enabled,
		int32(30), int32(20), int32(10), int32(3),
		now, now, "u1", "u1", time.Time{},
	)
}

func taskRunRows(now time.Time, runID, projectID, templateID, scopeID uint64, taskType, status string) *sqlmock.Rows {
	return sqlmock.NewRows(taskRunCols).AddRow(
		runID, "t1", "o1", projectID, templateID, scopeID,
		taskType, status,
		int32(0), int32(30), int32(20), int32(10), int32(3),
		int32(0), "", time.Time{}, time.Time{}, uint64(0), "",
		time.Time{}, time.Time{}, "", now, now, "u1", "u1", time.Time{},
	)
}

// Acceptance: GetScope is scoped by project_id and excludes soft-deleted rows.
func TestRepoGetScopeScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = ? AND project_id = ? AND "+softDeleteFilter)).
		WithArgs(uint64(7), uint64(1)).
		WillReturnRows(scopeRows(now, 7, 1, "prod-scope"))

	repo := NewRepository(dbgen.New(sqlDB))
	s, err := repo.GetScope(context.Background(), 1, 7)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), s.ID)
	assert.Equal(t, uint64(1), s.ProjectID)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: list queries carry the project scope and never return other projects.
func TestRepoListScopesByProjectScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta("WHERE project_id = ? AND " + softDeleteFilter)).
		WithArgs(uint64(3)).
		WillReturnRows(
			scopeRows(now, 3, 3, "scope-a").AddRow(
				uint64(4), "t1", "o1", uint64(3), "scope-b", StatusActive, "owner-ok",
				now, now.Add(time.Hour),
				now, now, "u1", "u1", time.Time{},
			),
		)

	repo := NewRepository(dbgen.New(sqlDB))
	scopes, err := repo.ListScopes(context.Background(), 3)
	require.NoError(t, err)
	assert.Len(t, scopes, 2)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: GetScope not found maps sql.ErrNoRows to discovery.ErrNotFound.
func TestRepoGetScopeNotFoundMapsErrNotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = ? AND project_id = ? AND "+softDeleteFilter)).
		WithArgs(uint64(9), uint64(1)).
		WillReturnError(sql.ErrNoRows)

	repo := NewRepository(dbgen.New(sqlDB))
	_, err = repo.GetScope(context.Background(), 1, 9)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: CreateScope issues a scope insert with project-scoped key fields.
func TestRepoCreateScopeWritesCoreFields(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO scope")).
		WithArgs(
			"t1", "o1", uint64(1),
			"prod", StatusActive, "owner",
			time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			"u1", "u1",
		).
		WillReturnResult(sqlmock.NewResult(99, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	id, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "prod",
		Status:       StatusActive,
		AuthorizedBy: "owner",
		ValidFrom:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil:   time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		ActorID:      "u1",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(99), id)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: UpdateScope is project-scoped and writes only expected columns.
func TestRepoUpdateScopeIsProjectScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectExec(regexp.QuoteMeta("UPDATE scope")).
		WithArgs("prod2", StatusInactive, "owner", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), "u2", uint64(7), uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.UpdateScope(context.Background(), UpdateScopeParams{
		ScopeID:      7,
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "prod2",
		Status:       StatusInactive,
		AuthorizedBy: "owner",
		ValidFrom:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil:   time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		ActorID:      "u2",
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: DeactivateScope updates status and updated_at in the project scope.
func TestRepoDeactivateScopeScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE scope")).
		WithArgs(StatusInactive, "u9", now, uint64(9), uint64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.DeactivateScope(context.Background(), 4, 9, "u9", func() time.Time { return now })
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: InsertScopeTarget persists project-scoped target rows.
func TestRepoInsertScopeTargetWritesProjectScopedTarget(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO scope_target")).
		WithArgs("t1", "o1", uint64(1), uint64(7), TargetTypeDomain, MatchModeInclude, "example.com", "u1", "u1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID:   "t1",
		OrgID:      "o1",
		ProjectID:  1,
		ScopeID:    7,
		TargetType: TargetTypeDomain,
		MatchMode:  MatchModeInclude,
		Value:      "example.com",
		ActorID:    "u1",
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: ListScopeTargets filters by project_id and scope_id and excludes tombstones.
func TestRepoListScopeTargetsScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta("WHERE scope_id = ? AND project_id = ? AND "+softDeleteFilter)).
		WithArgs(uint64(7), uint64(1)).
		WillReturnRows(scopeTargetRows(now, 7, 1, TargetTypeDomain, MatchModeInclude, "example.com"))

	repo := NewRepository(dbgen.New(sqlDB))
	targets, err := repo.ListScopeTargets(context.Background(), 1, 7)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "example.com", targets[0].Value)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: ClearScopeTargets scopes by project and scope and records actor + deleted_at.
func TestRepoClearScopeTargetsScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE scope_target")).
		WithArgs(now, "u1", uint64(7), uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.ClearScopeTargets(context.Background(), 1, 7, "u1", now)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoCreateTaskTemplateWritesProjectScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO task_template")).
		WithArgs(
			"t1", "o1", uint64(4),
			uint64(40), "scan", TaskTypeDNS,
			[]byte(`{"target":"example.com"}`), "*/10 * * * *", true,
			int32(30), int32(20), int32(10), int32(3),
			"u1", "u1",
		).
		WillReturnResult(sqlmock.NewResult(55, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	id, err := repo.CreateTaskTemplate(context.Background(), CreateTaskTemplateParams{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      4,
		ScopeID:        40,
		Name:           "scan",
		TaskType:       TaskTypeDNS,
		Config:         `{"target":"example.com"}`,
		Schedule:       "*/10 * * * *",
		Enabled:        true,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "u1",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(55), id)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoGetTaskTemplateByIDScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, scope_id, name, task_type, config, schedule, enabled, timeout_seconds, rate_limit, concurrency, retry_limit, created_at, updated_at, created_by, updated_by, deleted_at FROM task_template")).
		WithArgs(uint64(55), uint64(4)).
		WillReturnRows(taskTemplateRows(now, 55, 4, 40, "scan", TaskTypeDNS, true))

	repo := NewRepository(dbgen.New(sqlDB))
	template, err := repo.GetTaskTemplate(context.Background(), 4, 55)
	require.NoError(t, err)
	assert.Equal(t, uint64(55), template.ID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoUpdateTaskTemplateScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectExec(regexp.QuoteMeta("UPDATE task_template")).
		WithArgs(
			"scan-updated",
			TaskTypeWebProbe,
			[]byte(`{"target":"api.example.com"}`),
			"*/20 * * * *",
			int32(45), int32(30), int32(11), int32(4),
			"u2",
			uint64(56), uint64(5),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.UpdateTaskTemplate(context.Background(), UpdateTaskTemplateParams{
		TemplateID:     56,
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      5,
		Name:           "scan-updated",
		TaskType:       TaskTypeWebProbe,
		Config:         `{"target":"api.example.com"}`,
		Schedule:       "*/20 * * * *",
		TimeoutSeconds: 45,
		RateLimit:      30,
		Concurrency:    11,
		RetryLimit:     4,
		ActorID:        "u2",
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoCreateTaskRunWritesProjectScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Time{}
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO task_run")).
		WithArgs(
			"t1", "o1", uint64(6), uint64(77), uint64(66), TaskTypeDNS,
			TaskRunStatusPending, int32(0),
			int32(30), int32(20), int32(10), int32(3),
			int32(0), "", now, now, uint64(0),
			"", now, now, "", "u1", "u1",
		).
		WillReturnResult(sqlmock.NewResult(88, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	id, err := repo.CreateTaskRun(context.Background(), CreateTaskRunParams{
		TenantID:          "t1",
		OrgID:             "o1",
		ProjectID:         6,
		TemplateID:        77,
		ScopeID:           66,
		TaskType:          TaskTypeDNS,
		Status:            TaskRunStatusPending,
		Progress:          0,
		TimeoutSeconds:    30,
		RateLimit:         20,
		Concurrency:       10,
		RetryLimit:        3,
		Attempt:           0,
		EngineJobID:       "",
		DispatchedAt:      now,
		LastCallbackAt:    now,
		ResultCount:       0,
		CallbackSecretRef: "",
		StartedAt:         now,
		FinishedAt:        now,
		ErrorSummary:      "",
		ActorID:           "u1",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(88), id)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoMarkTaskRunRunningScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE task_run")).
		WithArgs(
			TaskRunStatusRunning,
			now,
			"u1",
			uint64(77),
			uint64(6),
			TaskRunStatusPending,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.MarkRunRunning(context.Background(), 6, 77, "u1", TaskRunStatusPending, now)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoMarkTaskRunRunningRejectedWhenTransitionNotMatch(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE task_run")).
		WithArgs(
			TaskRunStatusRunning,
			now,
			"u1",
			uint64(77),
			uint64(6),
			TaskRunStatusSuccess,
		).
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.MarkRunRunning(context.Background(), 6, 77, "u1", TaskRunStatusSuccess, now)
	require.ErrorIs(t, err, ErrInvalidRunTransition)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoMarkTaskRunDispatchedScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE task_run")).
		WithArgs(
			TaskRunStatusRunning,
			"engine-1",
			now,
			now,
			"u1",
			uint64(77),
			uint64(6),
			TaskRunStatusPending,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.MarkRunDispatched(context.Background(), 6, 77, "u1", TaskRunStatusPending, "engine-1", now)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoMarkTaskRunDispatchFailedScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE task_run")).
		WithArgs(
			TaskRunStatusFailed,
			"engine unavailable",
			now,
			"u1",
			uint64(77),
			uint64(6),
			TaskRunStatusPending,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.MarkRunDispatchFailed(context.Background(), 6, 77, "u1", TaskRunStatusPending, "engine unavailable", now)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoMarkTaskRunTerminalTransitionChecksFromStatus(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE task_run")).
		WithArgs(
			TaskRunStatusFailed,
			int32(0),
			uint64(2),
			"timeout",
			now,
			"u1",
			uint64(77),
			uint64(6),
			TaskRunStatusRunning,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.MarkRunFailed(context.Background(), 6, 77, "u1", TaskRunStatusRunning, "timeout", 2, now)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoListRunningRunsForReconcile(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, template_id, scope_id, task_type, status, progress, timeout_seconds, rate_limit, concurrency, retry_limit, attempt, engine_job_id, dispatched_at, last_callback_at, result_count, callback_secret_ref, started_at, finished_at, error_summary, created_at, updated_at, created_by, updated_by, deleted_at FROM task_run")).
		WithArgs(int32(20)).
		WillReturnRows(sqlmock.NewRows(taskRunCols).AddRow(
			uint64(77), "t1", "o1", uint64(6), uint64(5), uint64(4), TaskTypeDNS,
			TaskRunStatusRunning, int32(0), int32(60), int32(10), int32(2), int32(1),
			int32(1), "engine-1", now.Add(-time.Minute), time.Time{}, uint64(0), "",
			now.Add(-time.Minute), time.Time{}, "", now, now, "u1", "u1", time.Time{},
		))

	repo := NewRepository(dbgen.New(sqlDB))
	runs, err := repo.ListRunningRunsForReconcile(context.Background(), 20)
	require.NoError(t, err)
	require.Len(t, runs, 1)
	assert.Equal(t, uint64(77), runs[0].ID)
	assert.Equal(t, "engine-1", runs[0].EngineJobID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoInsertDiscoveryCallbackReportsDuplicate(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectExec(regexp.QuoteMeta("INSERT IGNORE INTO discovery_callback")).
		WithArgs(
			"t1", "o1", uint64(6), uint64(77), uint64(3),
			CallbackPhaseProgress, TaskRunStatusRunning, "abc123", uint64(2), "",
			now,
		).
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewRepository(dbgen.New(sqlDB))
	inserted, err := repo.InsertDiscoveryCallback(context.Background(), DiscoveryCallback{
		TenantID:    "t1",
		OrgID:       "o1",
		ProjectID:   6,
		RunID:       77,
		Seq:         3,
		Phase:       CallbackPhaseProgress,
		Status:      TaskRunStatusRunning,
		PayloadHash: "abc123",
		ResultCount: 2,
		ReceivedAt:  now,
	})
	require.NoError(t, err)
	assert.False(t, inserted)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRepoMarkTaskRunCallbackReceivedRequiresRunning(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE task_run")).
		WithArgs(
			now,
			uint64(2),
			"engine",
			uint64(77),
			uint64(6),
			TaskRunStatusRunning,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(dbgen.New(sqlDB))
	err = repo.MarkRunCallbackReceived(context.Background(), 6, 77, "engine", 2, now)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
