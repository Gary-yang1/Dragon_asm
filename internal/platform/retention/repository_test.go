package retention

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestRepositoryArchivesCurrentDiscoveryLedger(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock.ExpectExec(regexp.QuoteMeta("INSERT IGNORE INTO discovery_callback_archive")).
		WithArgs(cutoff, 100).
		WillReturnResult(sqlmock.NewResult(0, 7))

	n, err := NewRepository(sqlDB).ArchiveDiscoveryCallbacks(context.Background(), cutoff, 100)
	require.NoError(t, err)
	require.EqualValues(t, 7, n)
	require.NoError(t, mock.ExpectationsWereMet())
}
