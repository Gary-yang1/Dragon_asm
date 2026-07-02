package project_test

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
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

// projectCols mirrors the column order of SELECT * FROM project in the
// sqlc-generated query.
var projectCols = []string{
	"id", "tenant_id", "org_id", "project_code", "name", "owner", "business_unit",
	"criticality", "status", "description", "created_at", "updated_at", "created_by",
	"updated_by", "deleted_at",
}

// softDeleteFilter is the literal WHERE clause every live-row query must carry.
// Tests match against it to prove the repository excludes soft-deleted rows.
const softDeleteFilter = "deleted_at = '1970-01-01 00:00:00.000'"

// Acceptance: the GetByID query excludes soft-deleted rows (the SQL carries the
// sentinel filter), and maps the row into the domain Project.
func TestRepoGetByIDExcludesSoftDeleted(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = ? AND " + softDeleteFilter)).
		WithArgs(uint64(1)).
		WillReturnRows(
			sqlmock.NewRows(projectCols).
				AddRow(uint64(1), "t1", "o1", "alpha", "Alpha", "alice", "bu", "medium",
					"active", nil, now, now, "", "", time.Time{}),
		)

	repo := project.NewRepository(dbgen.New(sqlDB))
	p, err := repo.GetByID(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), p.ID)
	assert.Equal(t, "active", p.Status)
	assert.Equal(t, "", p.Description, "NULL description maps to empty string")
	require.NoError(t, mock.ExpectationsWereMet())
}

// A missing/soft-deleted project maps to the domain ErrNotFound.
func TestRepoGetByIDNotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = ? AND " + softDeleteFilter)).
		WithArgs(uint64(9)).
		WillReturnError(sql.ErrNoRows)

	repo := project.NewRepository(dbgen.New(sqlDB))
	_, err = repo.GetByID(context.Background(), 9)
	require.ErrorIs(t, err, project.ErrNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}

// IsMember: a member row -> true; no rows (non-member) -> false without error.
func TestRepoIsMember(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	repo := project.NewRepository(dbgen.New(sqlDB))

	// Member present.
	mock.ExpectQuery(regexp.QuoteMeta("FROM project_member")+".*"+regexp.QuoteMeta(softDeleteFilter)).
		WithArgs(uint64(1), "alice").
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("project_owner"))
	ok, err := repo.IsMember(context.Background(), 1, "alice")
	require.NoError(t, err)
	assert.True(t, ok)

	// Non-member -> sql.ErrNoRows -> false.
	mock.ExpectQuery(regexp.QuoteMeta("FROM project_member")+".*"+regexp.QuoteMeta(softDeleteFilter)).
		WithArgs(uint64(1), "carol").
		WillReturnError(sql.ErrNoRows)
	ok, err = repo.IsMember(context.Background(), 1, "carol")
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, mock.ExpectationsWereMet())
}
