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
