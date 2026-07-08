package discovery

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

func TestCreateScopeRollbackOnTargetInsertFailure(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO scope")).
		WithArgs(
			"t1", "o1", uint64(10),
			"policy", StatusInactive, "alice", now.Add(-time.Hour), now,
			"alice", "alice",
		).
		WillReturnResult(sqlmock.NewResult(7, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO scope_target")).
		WithArgs(
			"t1", "o1", uint64(10), uint64(7),
			TargetTypeDomain, MatchModeInclude, "example.com", "alice", "alice",
		).
		WillReturnError(sql.ErrConnDone)
	mock.ExpectRollback()

	svc := NewService(NewRepository(dbgen.New(sqlDB)), WithDB(sqlDB))
	_, err = svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    10,
		Name:         "policy",
		Status:       StatusInactive,
		AuthorizedBy: "alice",
		ValidFrom:    now.Add(-time.Hour),
		ValidUntil:   now,
		ActorID:      "alice",
		Targets: []ScopeTargetInput{
			{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com"},
		},
	})
	require.ErrorIs(t, err, sql.ErrConnDone)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateScopeRollbackOnAuditFailure(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	auditErr := errors.New("audit sink failure")

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO scope")).
		WithArgs(
			"t1", "o1", uint64(11),
			"policy", StatusActive, "alice", now.Add(-time.Hour), now,
			"alice", "alice",
		).
		WillReturnResult(sqlmock.NewResult(8, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO scope_target")).
		WithArgs(
			"t1", "o1", uint64(11), uint64(8),
			TargetTypeDomain, MatchModeInclude, "example.com", "alice", "alice",
		).
		WillReturnResult(sqlmock.NewResult(9, 1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, name, status, authorized_by, valid_from, valid_until, created_at, updated_at, created_by, updated_by, deleted_at FROM scope")).
		WithArgs(uint64(8), uint64(11)).
		WillReturnRows(scopeRows(now, 8, 11, "policy"))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).WillReturnError(auditErr)
	mock.ExpectRollback()

	svc := NewService(NewRepository(dbgen.New(sqlDB)), WithDB(sqlDB))
	_, err = svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    11,
		Name:         "policy",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    now.Add(-time.Hour),
		ValidUntil:   now,
		ActorID:      "alice",
		Targets: []ScopeTargetInput{
			{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com"},
		},
	})
	require.ErrorIs(t, err, auditErr)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateScopeRollbackOnTargetInsertFailure(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	newName := "new"

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, name, status, authorized_by, valid_from, valid_until, created_at, updated_at, created_by, updated_by, deleted_at FROM scope WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'")).
		WithArgs(uint64(12), uint64(12)).
		WillReturnRows(scopeRows(now, 12, 12, "old"))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE scope_target")).
		WithArgs(
			sqlmock.AnyArg(),
			"alice",
			uint64(12),
			uint64(12),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE scope")).
		WithArgs("new", StatusActive, "owner-ok", now.Add(-time.Hour), now.Add(time.Hour), "alice", uint64(12), uint64(12)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO scope_target")).
		WithArgs(
			"t1", "o1", uint64(12), uint64(12),
			TargetTypeIP, MatchModeInclude, "1.1.1.1", "alice", "alice",
		).
		WillReturnError(sql.ErrConnDone)
	mock.ExpectRollback()

	svc := NewService(NewRepository(dbgen.New(sqlDB)), WithDB(sqlDB))
	_, err = svc.UpdateScope(context.Background(), UpdateScopeInput{
		ScopeID:      12,
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    12,
		Name:         &newName,
		AuthorizedBy: nil,
		ValidFrom:    nil,
		ValidUntil:   nil,
		Status:       nil,
		ActorID:      "alice",
		Targets: &[]ScopeTargetInput{
			{TargetType: TargetTypeIP, MatchMode: MatchModeInclude, Value: "1.1.1.1"},
		},
	})
	require.ErrorIs(t, err, sql.ErrConnDone)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestDeactivateScopeRollbackOnAuditFailure(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	auditErr := errors.New("audit sink failure")

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, name, status, authorized_by, valid_from, valid_until, created_at, updated_at, created_by, updated_by, deleted_at FROM scope WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'")).
		WithArgs(uint64(13), uint64(13)).
		WillReturnRows(scopeRows(now, 13, 13, "deact"))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE scope")).
		WithArgs(StatusInactive, "alice", sqlmock.AnyArg(), uint64(13), uint64(13)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, name, status, authorized_by, valid_from, valid_until, created_at, updated_at, created_by, updated_by, deleted_at FROM scope WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'")).
		WithArgs(uint64(13), uint64(13)).
		WillReturnRows(scopeRows(now, 13, 13, "deact"))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).WillReturnError(auditErr)
	mock.ExpectRollback()

	svc := NewService(NewRepository(dbgen.New(sqlDB)), WithDB(sqlDB), WithNow(func() time.Time { return now }))
	err = svc.DeactivateScope(context.Background(), DeactivateScopeInput{
		ScopeID:   13,
		ProjectID: 13,
		ActorID:   "alice",
	})
	require.ErrorIs(t, err, auditErr)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateTaskTemplateRollbackOnAuditFailure(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now().UTC()
	auditErr := errors.New("audit sink failure")

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, name, status, authorized_by, valid_from, valid_until, created_at, updated_at, created_by, updated_by, deleted_at FROM scope WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'")).
		WithArgs(uint64(160), uint64(16)).
		WillReturnRows(scopeRows(now, 160, 16, "scope"))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO task_template")).
		WithArgs(
			"t1", "o1", uint64(16),
			uint64(160), "template", TaskTypeDNS, []byte(`{"target":"example.com"}`),
			"* * * * *", true,
			int32(30), int32(20), int32(10), int32(3),
			"alice", "alice",
		).
		WillReturnResult(sqlmock.NewResult(88, 1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, scope_id, name, task_type, config, schedule, enabled, timeout_seconds, rate_limit, concurrency, retry_limit, created_at, updated_at, created_by, updated_by, deleted_at FROM task_template")).
		WithArgs(uint64(88), uint64(16)).
		WillReturnRows(taskTemplateRows(now, 88, 16, 160, "template", TaskTypeDNS, true))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).WillReturnError(auditErr)
	mock.ExpectRollback()

	svc := NewService(NewRepository(dbgen.New(sqlDB)), WithDB(sqlDB))
	_, err = svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      16,
		ScopeID:        160,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         `{"target":"example.com"}`,
		Schedule:       "* * * * *",
		Enabled:        true,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	require.ErrorIs(t, err, auditErr)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateTaskRunRollbackOnAuditFailure(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Time{}
	auditErr := errors.New("audit sink failure")

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, scope_id, name, task_type, config, schedule, enabled, timeout_seconds, rate_limit, concurrency, retry_limit, created_at, updated_at, created_by, updated_by, deleted_at FROM task_template")).
		WithArgs(uint64(1700), uint64(17)).
		WillReturnRows(taskTemplateRows(now, 1700, 17, 170, "template", TaskTypeDNS, true))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO task_run")).
		WithArgs(
			"t1", "o1", uint64(17), uint64(1700), uint64(170),
			TaskTypeDNS, TaskRunStatusPending, int32(0),
			int32(30), int32(20), int32(10), int32(3), int32(0),
			"", now, now, uint64(0), "",
			now, now, "", "alice", "alice",
		).
		WillReturnResult(sqlmock.NewResult(int64(17000), 1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, template_id, scope_id, task_type, status, progress, timeout_seconds, rate_limit, concurrency, retry_limit, attempt, engine_job_id, dispatched_at, last_callback_at, result_count, callback_secret_ref, started_at, finished_at, error_summary, created_at, updated_at, created_by, updated_by, deleted_at FROM task_run")).
		WithArgs(uint64(17000), uint64(17)).
		WillReturnRows(taskRunRows(now, 17000, 17, 1700, 170, TaskTypeDNS, TaskRunStatusPending))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).WillReturnError(auditErr)
	mock.ExpectRollback()

	svc := NewService(NewRepository(dbgen.New(sqlDB)), WithDB(sqlDB))
	_, err = svc.CreateTaskRun(context.Background(), CreateTaskRunInput{
		TemplateID: 1700,
		ProjectID:  17,
		ActorID:    "alice",
	})
	require.ErrorIs(t, err, auditErr)

	require.NoError(t, mock.ExpectationsWereMet())
}
