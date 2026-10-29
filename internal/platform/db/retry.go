package db

import (
	"context"
	"errors"
	"time"

	"github.com/go-sql-driver/mysql"
)

// MySQL error numbers the server itself asks the client to retry.
const (
	errDeadlock         = 1213 // ER_LOCK_DEADLOCK — "try restarting transaction"
	errLockWaitTimeout  = 1205 // ER_LOCK_WAIT_TIMEOUT
	defaultTxAttempts   = 3
	defaultTxRetryDelay = 20 * time.Millisecond
)

// IsRetryableTxError reports whether err is a transient locking failure that
// MySQL expects the caller to resolve by re-running the transaction.
//
// InnoDB resolves a deadlock by rolling one transaction back and returning 1213;
// the work is not lost, it simply has to be attempted again. Treating it as a
// permanent failure is what left discovery callbacks stuck: three callbacks for
// one run ingest concurrently, each locking its own inbox row and then every row
// of the run, so one of them loses the deadlock and never completes.
func IsRetryableTxError(err error) bool {
	if err == nil {
		return false
	}
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == errDeadlock || mysqlErr.Number == errLockWaitTimeout
	}
	return false
}

// RetryOnLockConflict runs fn, re-running it while MySQL reports a deadlock or
// lock-wait timeout.
//
// fn must be safe to run more than once: it re-runs against a fresh transaction,
// so it has to read the state it depends on rather than closing over values read
// earlier. It stops immediately on any other error and on context cancellation.
func RetryOnLockConflict(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < defaultTxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			// A short, growing pause lets the winning transaction commit and release
			// its locks before the loser tries again.
			case <-time.After(time.Duration(attempt) * defaultTxRetryDelay):
			}
		}
		err = fn()
		if !IsRetryableTxError(err) {
			return err
		}
	}
	return err
}
