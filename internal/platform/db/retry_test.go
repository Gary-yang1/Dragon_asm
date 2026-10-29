package db_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/db"
)

func TestIsRetryableTxError(t *testing.T) {
	assert.True(t, db.IsRetryableTxError(&mysql.MySQLError{Number: 1213, Message: "Deadlock found"}))
	assert.True(t, db.IsRetryableTxError(&mysql.MySQLError{Number: 1205, Message: "Lock wait timeout"}))

	// Wrapped errors must still be recognised: the repository layer wraps driver
	// errors before they reach the transaction helper.
	wrapped := fmt.Errorf("ingest failed: %w", &mysql.MySQLError{Number: 1213})
	assert.True(t, db.IsRetryableTxError(wrapped))

	assert.False(t, db.IsRetryableTxError(nil))
	assert.False(t, db.IsRetryableTxError(errors.New("boom")))
	// A duplicate key is a real conflict; retrying it would loop on a permanent error.
	assert.False(t, db.IsRetryableTxError(&mysql.MySQLError{Number: 1062, Message: "Duplicate entry"}))
}

func TestRetryOnLockConflictRetriesUntilSuccess(t *testing.T) {
	attempts := 0
	err := db.RetryOnLockConflict(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return &mysql.MySQLError{Number: 1213, Message: "Deadlock found"}
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 3, attempts, "a deadlocked transaction must be re-run, not abandoned")
}

func TestRetryOnLockConflictGivesUpAndReturnsTheLastError(t *testing.T) {
	deadlock := &mysql.MySQLError{Number: 1213, Message: "Deadlock found"}
	attempts := 0
	err := db.RetryOnLockConflict(context.Background(), func() error {
		attempts++
		return deadlock
	})
	assert.ErrorIs(t, err, deadlock)
	assert.Equal(t, 3, attempts, "retries must be bounded so a persistent conflict cannot spin")
}

func TestRetryOnLockConflictDoesNotRetryOtherErrors(t *testing.T) {
	wantErr := errors.New("constraint violated")
	attempts := 0
	err := db.RetryOnLockConflict(context.Background(), func() error {
		attempts++
		return wantErr
	})
	assert.ErrorIs(t, err, wantErr)
	assert.Equal(t, 1, attempts, "only lock conflicts are retryable")
}

func TestRetryOnLockConflictStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := db.RetryOnLockConflict(ctx, func() error {
		attempts++
		cancel() // cancel before the retry pause
		return &mysql.MySQLError{Number: 1213}
	})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, attempts, "a cancelled caller must not keep retrying")
}

func TestRetryOnLockConflictSucceedsFirstTimeWithoutDelay(t *testing.T) {
	start := time.Now()
	require.NoError(t, db.RetryOnLockConflict(context.Background(), func() error { return nil }))
	assert.Less(t, time.Since(start), 10*time.Millisecond, "the happy path must not pay a retry pause")
}
