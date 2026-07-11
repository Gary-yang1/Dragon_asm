package discovery

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTimeoutReconciler struct {
	inputs []ReconcileTimedOutRunsInput
	err    error
}

func (f *fakeTimeoutReconciler) ReconcileTimedOutRuns(_ context.Context, in ReconcileTimedOutRunsInput) (ReconcileTimedOutRunsResult, error) {
	f.inputs = append(f.inputs, in)
	return ReconcileTimedOutRunsResult{Checked: 1}, f.err
}

func TestReconcileHandlerDecodesPayload(t *testing.T) {
	reconciler := &fakeTimeoutReconciler{}
	payload, err := json.Marshal(ReconcileTimedOutRunsPayload{Limit: 25, ActorID: "scheduler"})
	require.NoError(t, err)

	err = NewReconcileHandler(reconciler, nil).Handle(context.Background(), asynq.NewTask(TaskTypeReconcileTimedOutRun, payload))
	require.NoError(t, err)
	require.Len(t, reconciler.inputs, 1)
	assert.Equal(t, int32(25), reconciler.inputs[0].Limit)
	assert.Equal(t, "scheduler", reconciler.inputs[0].ActorID)
}

func TestReconcileHandlerDefaultsActor(t *testing.T) {
	reconciler := &fakeTimeoutReconciler{}
	err := NewReconcileHandler(reconciler, nil).Handle(context.Background(), asynq.NewTask(TaskTypeReconcileTimedOutRun, nil))
	require.NoError(t, err)
	require.Len(t, reconciler.inputs, 1)
	assert.Equal(t, "system", reconciler.inputs[0].ActorID)
}
