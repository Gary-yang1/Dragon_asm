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
	scopeCols       = []string{"id", "tenant_id", "org_id", "project_id", "name", "status", "authorized_by", "valid_from", "valid_until", "created_at", "updated_at", "created_by", "updated_by", "deleted_at"}
	scopeTargetCols = []string{"id", "tenant_id", "org_id", "project_id", "scope_id", "target_type", "match_mode", "target_value", "created_at", "updated_at", "created_by", "updated_by", "deleted_at"}
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
