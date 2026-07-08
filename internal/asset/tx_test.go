package asset_test

import (
	"context"
	"database/sql/driver"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// anyArgs builds n sqlmock.AnyArg matchers, so a tx test can match a statement's
// arguments without coupling to every value — the test asserts transaction
// control flow (Begin / Commit / Rollback), not argument values.
func anyArgs(n int) []driver.Value {
	args := make([]driver.Value, n)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	return args
}

const (
	upsertStmt   = "INSERT INTO asset"
	getByKeyStmt = "WHERE project_id = ? AND asset_key = ?"
	auditStmt    = "INSERT INTO audit_log"
)

// Acceptance: when the audit write fails, the whole import transaction is
// rolled back — a committed asset change must never exist without its audit
// record. This exercises the production (WithDB) transactional path with a real
// *sql.Tx backed by sqlmock.
func TestImportBatchRollsBackOnAuditFailure(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	svc := asset.NewService(asset.NewRepository(dbgen.New(sqlDB)), asset.WithDB(sqlDB))

	mock.ExpectBegin()
	// Asset upsert + re-read succeed within the tx...
	mock.ExpectExec(regexp.QuoteMeta(upsertStmt)).WithArgs(anyArgs(16)...).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(regexp.QuoteMeta(getByKeyStmt)).WithArgs(anyArgs(2)...).
		WillReturnRows(assetRow(1, 1, "domain:example.com"))
	// ...but the audit insert fails, so the tx must roll back (no commit).
	mock.ExpectExec(regexp.QuoteMeta(auditStmt)).WithArgs(anyArgs(17)...).
		WillReturnError(errors.New("audit store down"))
	mock.ExpectRollback()

	_, err = svc.ImportBatch(context.Background(), asset.ImportBatchInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1", ActorID: "u1",
		Rows: []asset.ImportInput{{AssetType: asset.TypeDomain, Value: "example.com"}},
	}, asset.AuditMeta{})
	require.Error(t, err, "audit failure must surface as an error, not a silent success")
	require.NoError(t, mock.ExpectationsWereMet(), "Rollback must be called (no Commit)")
}

// Acceptance: when the audit write succeeds, the import transaction commits.
func TestImportBatchCommitsOnSuccess(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	svc := asset.NewService(asset.NewRepository(dbgen.New(sqlDB)), asset.WithDB(sqlDB))

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(upsertStmt)).WithArgs(anyArgs(16)...).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(regexp.QuoteMeta(getByKeyStmt)).WithArgs(anyArgs(2)...).
		WillReturnRows(assetRow(1, 1, "domain:example.com"))
	mock.ExpectExec(regexp.QuoteMeta(auditStmt)).WithArgs(anyArgs(17)...).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	report, err := svc.ImportBatch(context.Background(), asset.ImportBatchInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1", ActorID: "u1",
		Rows: []asset.ImportInput{{AssetType: asset.TypeDomain, Value: "example.com"}},
	}, asset.AuditMeta{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), report.Success)
	require.NoError(t, mock.ExpectationsWereMet(), "Commit must be called")
}

// Acceptance: an edit whose audit write fails is rolled back (no committed edit
// without an audit record).
func TestUpdateRollsBackOnAuditFailure(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	svc := asset.NewService(asset.NewRepository(dbgen.New(sqlDB)), asset.WithDB(sqlDB))

	owner := "bob"
	mock.ExpectBegin()
	// before read
	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = ? AND project_id = ?")).WithArgs(anyArgs(2)...).
		WillReturnRows(assetRow(7, 1, "domain:example.com"))
	// update write
	mock.ExpectExec(regexp.QuoteMeta("UPDATE asset")).WithArgs(anyArgs(8)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// after read
	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = ? AND project_id = ?")).WithArgs(anyArgs(2)...).
		WillReturnRows(assetRow(7, 1, "domain:example.com"))
	// audit insert fails -> rollback
	mock.ExpectExec(regexp.QuoteMeta(auditStmt)).WithArgs(anyArgs(17)...).
		WillReturnError(errors.New("audit store down"))
	mock.ExpectRollback()

	_, err = svc.Update(context.Background(), 1, 7, asset.UpdateFields{Owner: &owner}, "u1", asset.AuditMeta{})
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet(), "Rollback must be called (no Commit)")
}
