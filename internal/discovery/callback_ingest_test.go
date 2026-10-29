package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runningCallbackFixture(t *testing.T) (*Service, *TaskRun, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = &fakeCallbackEnqueuer{}
	svc.engine = &fakeEngine{ids: []string{"job-ingest"}}
	dispatched, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "alice"})
	require.NoError(t, err)
	return svc, dispatched, now
}

func acceptCallbackForIngest(t *testing.T, svc *Service, now time.Time, runID, seq uint64, phase, status string, count int) {
	t.Helper()
	raw := validCallbackRaw(t, runID, seq, phase, status, count)
	_, err := svc.HandleCallback(context.Background(), signedCallbackInput(1, runID, seq, now, "secret", raw))
	require.NoError(t, err)
}

func TestFinalCallbackWaitsForEarlierSequenceAndCountsOnce(t *testing.T) {
	svc, run, now := runningCallbackFixture(t)
	acceptCallbackForIngest(t, svc, now, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 1)
	acceptCallbackForIngest(t, svc, now, run.ID, 2, CallbackPhaseCompleted, TaskRunStatusSuccess, 1)

	claimed, err := svc.ClaimDiscoveryCallbackIngest(context.Background(), 1, run.ID, 2)
	require.NoError(t, err)
	require.True(t, claimed)
	result, err := svc.CompleteDiscoveryCallbackIngest(context.Background(), 1, run.ID, 2)
	require.NoError(t, err)
	assert.True(t, result.Processed)
	assert.False(t, result.Finalized)
	after, err := svc.GetTaskRun(context.Background(), 1, run.ID)
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusRunning, after.Status)
	assert.Equal(t, uint64(1), after.ResultCount)

	claimed, err = svc.ClaimDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	require.True(t, claimed)
	result, err = svc.CompleteDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	assert.True(t, result.Finalized)
	after, err = svc.GetTaskRun(context.Background(), 1, run.ID)
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusSuccess, after.Status)
	assert.Equal(t, uint64(2), after.ResultCount)

	result, err = svc.CompleteDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	assert.False(t, result.Processed)
	after, err = svc.GetTaskRun(context.Background(), 1, run.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), after.ResultCount)
}

func TestProgressCallbackDoesNotFinalizeRun(t *testing.T) {
	svc, run, now := runningCallbackFixture(t)
	acceptCallbackForIngest(t, svc, now, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	claimed, err := svc.ClaimDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	require.True(t, claimed)
	result, err := svc.CompleteDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	assert.False(t, result.Finalized)
	after, err := svc.GetTaskRun(context.Background(), 1, run.ID)
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusRunning, after.Status)
}

func TestCallbackFinalStateMappings(t *testing.T) {
	tests := []struct {
		phase string
		input string
		want  string
	}{
		{CallbackPhaseCompleted, TaskRunStatusSuccess, TaskRunStatusSuccess},
		{CallbackPhaseCompleted, TaskRunStatusPartial, TaskRunStatusPartial},
		{CallbackPhaseCompleted, TaskRunStatusCancelled, TaskRunStatusCancelled},
		{CallbackPhaseFailed, TaskRunStatusFailed, TaskRunStatusFailed},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			status, _, ready, err := callbackFinalState([]*DiscoveryCallback{{
				Seq: 1, Phase: tt.phase, Status: tt.input, IngestStatus: CallbackIngestProcessed,
			}})
			require.NoError(t, err)
			assert.True(t, ready)
			assert.Equal(t, tt.want, status)
		})
	}
}

// processedCallback is a shorthand for an already-ingested inbox row.
func processedCallback(seq uint64, phase, status string) *DiscoveryCallback {
	return &DiscoveryCallback{Seq: seq, Phase: phase, Status: status, IngestStatus: CallbackIngestProcessed}
}

// A callback numbered beyond the engine's final marker is a protocol violation by
// the sender. It must not hold the run open: before this, one injected seq left the
// run in `running` until the reconcile worker timed it out, so a successful scan was
// recorded as a timeout and the asset lifecycle pass never ran.
func TestCallbackFinalStateIgnoresCallbacksBeyondTheFinalMarker(t *testing.T) {
	callbacks := []*DiscoveryCallback{
		processedCallback(1, CallbackPhaseProgress, TaskRunStatusRunning),
		processedCallback(2, CallbackPhaseCompleted, TaskRunStatusSuccess),
		processedCallback(999999, CallbackPhaseProgress, TaskRunStatusRunning),
	}

	status, _, ready, err := callbackFinalState(callbacks)
	require.NoError(t, err)
	assert.True(t, ready, "an out-of-contract extra must not block finalisation")
	assert.Equal(t, TaskRunStatusSuccess, status)
}

// An unprocessed extra beyond the marker must not block either — otherwise a single
// poisoned row keeps the run open forever.
func TestCallbackFinalStateIgnoresUnprocessedExtraBeyondMarker(t *testing.T) {
	callbacks := []*DiscoveryCallback{
		processedCallback(1, CallbackPhaseCompleted, TaskRunStatusSuccess),
		{Seq: 500, Phase: CallbackPhaseProgress, Status: TaskRunStatusRunning, IngestStatus: CallbackIngestPending},
	}

	status, _, ready, err := callbackFinalState(callbacks)
	require.NoError(t, err)
	assert.True(t, ready)
	assert.Equal(t, TaskRunStatusSuccess, status)
}

// A genuine gap below the marker means facts are still missing, so the run must
// keep waiting rather than finalise on partial data.
func TestCallbackFinalStateWaitsOnGapBelowTheMarker(t *testing.T) {
	callbacks := []*DiscoveryCallback{
		processedCallback(1, CallbackPhaseProgress, TaskRunStatusRunning),
		// seq 2 has not arrived yet.
		processedCallback(3, CallbackPhaseCompleted, TaskRunStatusSuccess),
	}

	_, _, ready, err := callbackFinalState(callbacks)
	require.NoError(t, err)
	assert.False(t, ready, "a missing callback below the final marker must block finalisation")
}

// An unprocessed callback below the marker must also block.
func TestCallbackFinalStateWaitsOnUnprocessedCallbackBelowMarker(t *testing.T) {
	callbacks := []*DiscoveryCallback{
		{Seq: 1, Phase: CallbackPhaseProgress, Status: TaskRunStatusRunning, IngestStatus: CallbackIngestPending},
		processedCallback(2, CallbackPhaseCompleted, TaskRunStatusSuccess),
	}

	_, _, ready, err := callbackFinalState(callbacks)
	require.NoError(t, err)
	assert.False(t, ready)
}

// When the engine contradicts a completion it already declared, the first marker
// wins and the run still closes. Surfacing an error here would roll the ingest back
// and retry it forever, which is the failure mode being fixed.
func TestCallbackFinalStateFirstFinalMarkerWins(t *testing.T) {
	callbacks := []*DiscoveryCallback{
		processedCallback(1, CallbackPhaseCompleted, TaskRunStatusSuccess),
		processedCallback(2, CallbackPhaseFailed, TaskRunStatusFailed),
	}

	status, _, ready, err := callbackFinalState(callbacks)
	require.NoError(t, err)
	assert.True(t, ready)
	assert.Equal(t, TaskRunStatusSuccess, status, "the earlier declared completion is authoritative")
}

// The inbox is indexed by seq, so an absurd value is refused at the door.
func TestHandleCallbackRejectsOutOfRangeSeq(t *testing.T) {
	svc, run, now := runningCallbackFixture(t)
	raw := validCallbackRaw(t, run.ID, callbackMaxSeq+1, CallbackPhaseProgress, TaskRunStatusRunning, 1)

	_, err := svc.HandleCallback(context.Background(),
		signedCallbackInput(1, run.ID, callbackMaxSeq+1, now, "secret", raw))
	assert.ErrorIs(t, err, ErrInvalidCallbackPayload)
}

// End to end through the service: an injected out-of-contract callback used to keep
// the run in `running`; the real final callback must still close it.
func TestRunFinalisesDespiteInjectedOutOfContractCallback(t *testing.T) {
	svc, run, now := runningCallbackFixture(t)

	// A wild seq slipped into the inbox alongside the legitimate stream.
	acceptCallbackForIngest(t, svc, now, run.ID, 900, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	acceptCallbackForIngest(t, svc, now, run.ID, 1, CallbackPhaseCompleted, TaskRunStatusSuccess, 2)

	claimed, err := svc.ClaimDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	require.True(t, claimed)
	result, err := svc.CompleteDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	assert.True(t, result.Finalized, "the run must close on its final callback")

	after, err := svc.GetTaskRun(context.Background(), 1, run.ID)
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusSuccess, after.Status)
}

// The realistic straggler: an out-of-contract callback is accepted while the run is
// still running, the run then closes on its real final callback, and only afterwards
// does the recovery worker get around to ingesting the extra. That ingest must be a
// no-op — erroring rolls back the "processed" mark and the worker retries the same
// row until its attempt budget is exhausted, leaving it permanently failed.
func TestIngestingOutOfContractExtraAfterFinalisationIsIdempotent(t *testing.T) {
	svc, run, now := runningCallbackFixture(t)

	// Accepted while running, so it lands in the inbox as pending.
	acceptCallbackForIngest(t, svc, now, run.ID, 900, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	acceptCallbackForIngest(t, svc, now, run.ID, 1, CallbackPhaseCompleted, TaskRunStatusSuccess, 1)

	claimed, err := svc.ClaimDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	require.True(t, claimed)
	_, err = svc.CompleteDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	after, err := svc.GetTaskRun(context.Background(), 1, run.ID)
	require.NoError(t, err)
	require.Equal(t, TaskRunStatusSuccess, after.Status)

	// Now drain the leftover extra against an already-closed run.
	claimed, err = svc.ClaimDiscoveryCallbackIngest(context.Background(), 1, run.ID, 900)
	require.NoError(t, err)
	require.True(t, claimed)
	result, err := svc.CompleteDiscoveryCallbackIngest(context.Background(), 1, run.ID, 900)
	require.NoError(t, err, "draining a leftover extra must not error and trigger endless retries")
	assert.True(t, result.Processed)

	// The run keeps the result it finalised with.
	after, err = svc.GetTaskRun(context.Background(), 1, run.ID)
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusSuccess, after.Status)
}
