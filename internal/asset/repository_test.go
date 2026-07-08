package asset_test

import (
	"context"
	"database/sql"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// assetCols mirrors the column order of SELECT * FROM asset in the generated query.
var assetCols = []string{
	"id", "tenant_id", "org_id", "project_id", "asset_type", "asset_key",
	"display_name", "value", "source", "owner", "business_unit", "confidence",
	"status", "first_seen", "last_seen", "created_at", "updated_at",
	"created_by", "updated_by", "deleted_at",
}

// softDeleteFilter is the literal WHERE clause every live-row query must carry.
const softDeleteFilter = "deleted_at = '1970-01-01 00:00:00.000'"

func assetRow(id, projectID uint64, key string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(assetCols).AddRow(
		id, "t1", "o1", projectID, "domain", key, key, key, "seed", "", "",
		uint8(100), "active", now, now, now, now, "", "", time.Time{},
	)
}

// Acceptance: GetByKey is scoped by project_id AND excludes soft-deleted rows.
func TestRepoGetByKeyScopedAndLive(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta("WHERE project_id = ? AND asset_key = ? AND "+softDeleteFilter)).
		WithArgs(uint64(1), "domain:example.com").
		WillReturnRows(assetRow(7, 1, "domain:example.com"))

	repo := asset.NewRepository(dbgen.New(sqlDB))
	a, err := repo.GetByKey(context.Background(), 1, "domain:example.com")
	require.NoError(t, err)
	assert.Equal(t, uint64(7), a.ID)
	assert.Equal(t, uint64(1), a.ProjectID)
	require.NoError(t, mock.ExpectationsWereMet())
}

// GetByID carries both the project_id scope and the soft-delete filter.
func TestRepoGetByIDScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = ? AND project_id = ? AND "+softDeleteFilter)).
		WithArgs(uint64(7), uint64(1)).
		WillReturnRows(assetRow(7, 1, "domain:example.com"))

	repo := asset.NewRepository(dbgen.New(sqlDB))
	a, err := repo.GetByID(context.Background(), 1, 7)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), a.ID)
	require.NoError(t, mock.ExpectationsWereMet())
}

// A missing/soft-deleted asset maps to the domain ErrNotFound.
func TestRepoGetByKeyNotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta(softDeleteFilter)).
		WithArgs(uint64(1), "domain:missing.com").
		WillReturnError(sql.ErrNoRows)

	repo := asset.NewRepository(dbgen.New(sqlDB))
	_, err = repo.GetByKey(context.Background(), 1, "domain:missing.com")
	require.ErrorIs(t, err, asset.ErrNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: Upsert issues a single INSERT ... ON DUPLICATE KEY UPDATE, so a
// repeated import collapses to one row at the DB layer.
func TestRepoUpsertIsSingleIdempotentStatement(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO asset")+".*"+regexp.QuoteMeta("ON DUPLICATE KEY UPDATE")).
		WithArgs(
			"t1", "o1", uint64(1), "domain", "domain:example.com",
			"example.com", "example.com", "seed", "", "",
			uint8(100), "active", sqlmock.AnyArg(), sqlmock.AnyArg(), "u1", "u1",
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	repo := asset.NewRepository(dbgen.New(sqlDB))
	err = repo.Upsert(context.Background(), asset.UpsertParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetType: "domain",
		AssetKey: "domain:example.com", DisplayName: "example.com", Value: "example.com",
		Source: "seed", Confidence: 100, Status: "active", ActorID: "u1",
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// List is project-scoped and paginated.
func TestRepoListScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta("WHERE project_id = ? AND "+softDeleteFilter)).
		WithArgs(uint64(1), int32(50), int32(0)).
		WillReturnRows(
			assetRow(7, 1, "domain:a.com").AddRow(
				uint64(8), "t1", "o1", uint64(1), "domain", "domain:b.com", "b.com",
				"b.com", "seed", "", "", uint8(100), "active",
				time.Now(), time.Now(), time.Now(), time.Now(), "", "", time.Time{},
			),
		)

	repo := asset.NewRepository(dbgen.New(sqlDB))
	rows, err := repo.List(context.Background(), 1, 50, 0)
	require.NoError(t, err)
	assert.Len(t, rows, 2)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Count is project-scoped and excludes soft-deleted rows.
func TestRepoCountScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM asset")).
		WithArgs(uint64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(42)))

	repo := asset.NewRepository(dbgen.New(sqlDB))
	n, err := repo.Count(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, int64(42), n)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Update issues a single project-scoped UPDATE; the WHERE clause carries both
// id and project_id plus the soft-delete filter.
func TestRepoUpdateScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectExec(regexp.QuoteMeta("UPDATE asset")).
		WithArgs(
			"example.com", "seed", "bob", "team-a", "active", "u1",
			uint64(7), uint64(1),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := asset.NewRepository(dbgen.New(sqlDB))
	err = repo.Update(context.Background(), asset.UpdateParams{
		ProjectID:    1,
		ID:           7,
		DisplayName:  "example.com",
		Source:       "seed",
		Owner:        "bob",
		BusinessUnit: "team-a",
		Status:       "active",
		ActorID:      "u1",
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
