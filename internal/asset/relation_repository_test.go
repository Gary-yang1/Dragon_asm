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

// relationCols mirrors the column order of SELECT * FROM asset_relation.
var relationCols = []string{
	"id", "tenant_id", "org_id", "project_id", "from_asset_id", "to_asset_id",
	"relation_type", "source", "confidence", "first_seen", "last_seen",
	"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
}

func relationRow(id, projectID, fromID, toID uint64, relType string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(relationCols).AddRow(
		id, "t1", "o1", projectID, fromID, toID, relType, "seed", uint8(80),
		now, now, now, now, "u1", "u1", time.Time{},
	)
}

// Upsert issues a single idempotent INSERT ... ON DUPLICATE KEY UPDATE.
func TestRepoUpsertRelationSingleStatement(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO asset_relation")+".*"+regexp.QuoteMeta("ON DUPLICATE KEY UPDATE")).
		WithArgs(
			"t1", "o1", uint64(1), uint64(10), uint64(20), "resolves_to",
			"seed", uint8(80), sqlmock.AnyArg(), sqlmock.AnyArg(), "u1", "u1",
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	repo := asset.NewRelationRepository(dbgen.New(sqlDB))
	err = repo.Upsert(context.Background(), asset.UpsertRelationParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, FromAssetID: 10, ToAssetID: 20,
		RelationType: asset.RelationResolvesTo, Source: "seed", Confidence: 80, ActorID: "u1",
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// ListByAsset is project-scoped, bidirectional, and excludes soft-deleted rows.
func TestRepoListRelationsScopedAndLive(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta("WHERE project_id = ? AND (from_asset_id = ? OR to_asset_id = ?) AND "+softDeleteFilter)).
		WithArgs(uint64(1), uint64(10), uint64(10), int32(50), int32(0)).
		WillReturnRows(
			relationRow(1, 1, 10, 20, "resolves_to").AddRow(
				uint64(2), "t1", "o1", uint64(1), uint64(30), uint64(10), "contains", "seed", uint8(80),
				time.Now(), time.Now(), time.Now(), time.Now(), "u1", "u1", time.Time{},
			),
		)

	repo := asset.NewRelationRepository(dbgen.New(sqlDB))
	rows, err := repo.ListByAsset(context.Background(), 1, 10, 50, 0)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	// Direction is tagged relative to the queried asset (10): row 1 is out, row 2 is in.
	assert.Equal(t, asset.DirectionOut, rows[0].Direction)
	assert.Equal(t, asset.DirectionIn, rows[1].Direction)
	require.NoError(t, mock.ExpectationsWereMet())
}

// CountByAsset carries the same project + soft-delete + bidirectional filter.
func TestRepoCountRelationsScoped(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM asset_relation")).
		WithArgs(uint64(1), uint64(10), uint64(10)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(3)))

	repo := asset.NewRelationRepository(dbgen.New(sqlDB))
	n, err := repo.CountByAsset(context.Background(), 1, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
	require.NoError(t, mock.ExpectationsWereMet())
}

// GetByEndpoints maps a missing row to the domain ErrNotFound.
func TestRepoGetRelationByEndpointsNotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(regexp.QuoteMeta("WHERE project_id = ? AND from_asset_id = ? AND to_asset_id = ? AND relation_type = ? AND "+softDeleteFilter)).
		WithArgs(uint64(1), uint64(10), uint64(20), "resolves_to").
		WillReturnError(sql.ErrNoRows)

	repo := asset.NewRelationRepository(dbgen.New(sqlDB))
	_, err = repo.GetByEndpoints(context.Background(), 1, 10, 20, asset.RelationResolvesTo)
	require.ErrorIs(t, err, asset.ErrNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}
