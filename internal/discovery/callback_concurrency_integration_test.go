//go:build integration

package discovery

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// A large passive job sends a burst of callbacks that the worker completes
// concurrently. Completion used to lock its own callback row, then the run,
// then every callback of the run, so two completions of one run deadlocked;
// on the test environment 51 of 192 callbacks stalled in "processing" and the
// run never closed. Completions must now queue on the run lock instead.
func TestConcurrentCallbackCompletionsOfOneRunDoNotDeadlock(t *testing.T) {
	dsn := os.Getenv("ASM_CALLBACK_CONCURRENCY_TEST_DSN")
	if dsn == "" {
		t.Skip("ASM_CALLBACK_CONCURRENCY_TEST_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(40)
	require.NoError(t, db.Ping())

	ctx := context.Background()
	runID := seedIntegrationRun(t, db)
	repo := NewRepository(dbgen.New(db))
	svc := NewService(repo, WithDB(db))

	const callbacks = 60
	observed := time.Date(2026, time.October, 29, 9, 38, 0, 0, time.UTC)
	for seq := uint64(1); seq <= callbacks; seq++ {
		phase, status := CallbackPhaseProgress, TaskRunStatusRunning
		if seq == callbacks {
			phase, status = CallbackPhaseCompleted, TaskRunStatusSuccess
		}
		raw := []byte(`{}`)
		inserted, err := repo.InsertDiscoveryCallback(ctx, DiscoveryCallback{
			TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, RunID: runID, Seq: seq,
			SchemaVersion: callbackSchemaVersion, Phase: phase, Status: status, ObservedAt: observed,
			PayloadHash: callbackPayloadHash(raw), Payload: raw, PayloadSize: uint32(len(raw)),
			ReceivedAt: observed, IngestStatus: CallbackIngestProcessing,
		})
		require.NoError(t, err)
		require.True(t, inserted)
	}

	start := make(chan struct{})
	errs := make(chan error, callbacks)
	sem := make(chan struct{}, 20) // the worker's asynq concurrency is 10; go beyond it
	var wg sync.WaitGroup
	for seq := uint64(1); seq <= callbacks; seq++ {
		wg.Add(1)
		go func(seq uint64) {
			defer wg.Done()
			<-start
			sem <- struct{}{}
			defer func() { <-sem }()
			_, err := svc.CompleteDiscoveryCallbackIngest(ctx, 1, runID, seq)
			errs <- err
		}(seq)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	require.Equal(t, int64(callbacks), scalarCount(t, db,
		"SELECT COUNT(*) FROM discovery_callback WHERE project_id=1 AND run_id=? AND ingest_status='processed'", runID))
	var status string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT status FROM task_run WHERE id=?", runID).Scan(&status))
	require.Equal(t, TaskRunStatusSuccess, status, "the completed callback must close the run once every callback is processed")
}
