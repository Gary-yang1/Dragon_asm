package retention

import (
	"context"
	"database/sql/driver"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestRunArchivesDeletesAndAuditsInOneTransaction(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	expectRetentionExec(mock, "INSERT IGNORE INTO audit_log_archive", 2)
	expectRetentionExec(mock, "DELETE al FROM audit_log", 2)
	expectRetentionExec(mock, "INSERT IGNORE INTO change_event_archive", 3)
	expectRetentionExec(mock, "DELETE ce FROM change_event", 3)
	expectRetentionExec(mock, "INSERT IGNORE INTO discovery_callback_archive", 4)
	expectRetentionExec(mock, "DELETE dc FROM discovery_callback", 4)
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(anyAuditArgs()...).
		WillReturnResult(sqlmock.NewResult(99, 1))
	mock.ExpectCommit()

	stats, err := NewService(sqlDB, WithNow(func() time.Time { return now })).Run(context.Background(), Policy{
		AuditMinRetentionDays:       365,
		AuditArchiveAfterDays:       400,
		ChangeEventArchiveAfterDays: 200,
		DiscoveryCallbackAfterDays:  100,
		BatchSize:                   500,
		ActorID:                     "worker-1",
	})
	require.NoError(t, err)
	require.Equal(t, Stats{
		AuditLogsArchived:          2,
		AuditLogsDeleted:           2,
		ChangeEventsArchived:       3,
		ChangeEventsDeleted:        3,
		DiscoveryCallbacksArchived: 4,
		DiscoveryCallbacksDeleted:  4,
	}, stats)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRunRejectsAuditRetentionBelowFloor(t *testing.T) {
	sqlDB, _, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	_, err = NewService(sqlDB).Run(context.Background(), Policy{
		AuditMinRetentionDays:       365,
		AuditArchiveAfterDays:       30,
		ChangeEventArchiveAfterDays: 180,
		DiscoveryCallbackAfterDays:  90,
		BatchSize:                   100,
	})
	require.ErrorIs(t, err, ErrAuditRetentionFloor)
}

func TestRunRollsBackWhenAuditFails(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	auditErr := errors.New("audit unavailable")
	mock.ExpectBegin()
	expectRetentionExec(mock, "INSERT IGNORE INTO audit_log_archive", 1)
	expectRetentionExec(mock, "DELETE al FROM audit_log", 1)
	expectRetentionExec(mock, "INSERT IGNORE INTO change_event_archive", 1)
	expectRetentionExec(mock, "DELETE ce FROM change_event", 1)
	expectRetentionExec(mock, "INSERT IGNORE INTO discovery_callback_archive", 1)
	expectRetentionExec(mock, "DELETE dc FROM discovery_callback", 1)
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(anyAuditArgs()...).
		WillReturnError(auditErr)
	mock.ExpectRollback()

	_, err = NewService(sqlDB).Run(context.Background(), DefaultPolicy())
	require.ErrorIs(t, err, auditErr)
	require.NoError(t, mock.ExpectationsWereMet())
}

func expectRetentionExec(mock sqlmock.Sqlmock, sqlPrefix string, affected int64) {
	mock.ExpectExec(regexp.QuoteMeta(sqlPrefix)).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, affected))
}

func anyAuditArgs() []driver.Value {
	args := make([]driver.Value, 17)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	return args
}
