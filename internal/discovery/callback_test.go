package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mutateCallbackJSON(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	require.NoError(t, json.Unmarshal(raw, &value))
	mutate(value)
	result, err := json.Marshal(value)
	require.NoError(t, err)
	return result
}

func TestParseCallbackPayloadStrictV1(t *testing.T) {
	valid := validCallbackRaw(t, 7, 1, CallbackPhaseProgress, TaskRunStatusRunning, 1)
	parsed, err := parseCallbackPayload(valid)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), parsed.RunID)
	assert.Len(t, parsed.Assets, 1)

	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{name: "unknown field", mutate: func(v map[string]any) { v["unexpected"] = true }, want: ErrInvalidCallbackPayload},
		{name: "unsupported schema", mutate: func(v map[string]any) { v["schema_version"] = "2.0" }, want: ErrCallbackSchemaUnsupported},
		{name: "missing required array", mutate: func(v map[string]any) { delete(v, "relations") }, want: ErrInvalidCallbackPayload},
		{name: "null required array", mutate: func(v map[string]any) { v["exposures"] = nil }, want: ErrInvalidCallbackPayload},
		{name: "too many assets", mutate: func(v map[string]any) { v["assets"] = make([]any, callbackMaxAssets+1) }, want: ErrInvalidCallbackPayload},
		{name: "count mismatch", mutate: func(v map[string]any) { v["result_count"] = 0 }, want: ErrInvalidCallbackPayload},
		{name: "active probe forbidden", mutate: func(v map[string]any) {
			v["assets"].([]any)[0].(map[string]any)["active_probe"] = true
		}, want: ErrInvalidCallbackPayload},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCallbackPayload(mutateCallbackJSON(t, valid, tt.mutate))
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestHandleCallbackConflictDoesNotOverwriteInbox(t *testing.T) {
	now := time.Now().UTC()
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = &fakeCallbackEnqueuer{}
	svc.engine = &fakeEngine{ids: []string{"job-conflict"}}
	_, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "alice"})
	require.NoError(t, err)

	first := validCallbackRaw(t, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	require.NoError(t, func() error {
		_, err := svc.HandleCallback(context.Background(), signedCallbackInput(1, run.ID, 1, now, "secret", first))
		return err
	}())
	second := mutateCallbackJSON(t, first, func(v map[string]any) { v["error_summary"] = "different" })
	_, err = svc.HandleCallback(context.Background(), signedCallbackInput(1, run.ID, 1, now, "secret", second))
	assert.ErrorIs(t, err, ErrCallbackPayloadConflict)

	stored, err := svc.repo.GetDiscoveryCallback(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	assert.JSONEq(t, string(first), string(stored.Payload))
}

func TestHandleCallbackQueueFailureIsRecoverable(t *testing.T) {
	now := time.Now().UTC()
	enqueuer := &fakeCallbackEnqueuer{err: errors.New("redis unavailable")}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = enqueuer
	svc.engine = &fakeEngine{ids: []string{"job-recovery"}}
	_, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "alice"})
	require.NoError(t, err)

	raw := validCallbackRaw(t, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	_, err = svc.HandleCallback(context.Background(), signedCallbackInput(1, run.ID, 1, now, "secret", raw))
	assert.ErrorIs(t, err, ErrCallbackEnqueue)
	stored, err := svc.repo.GetDiscoveryCallback(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	assert.Equal(t, CallbackIngestPending, stored.IngestStatus)
	assert.NotEmpty(t, stored.Payload)

	enqueuer.err = nil
	recovered, err := svc.RecoverPendingCallbacks(context.Background(), 100)
	require.NoError(t, err)
	assert.Equal(t, 1, recovered)
	assert.Equal(t, 1, enqueuer.calls)
}

func TestHandleCallbackRejectsRunSecretRefMismatch(t *testing.T) {
	now := time.Now().UTC()
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = &fakeCallbackEnqueuer{}
	svc.engine = &fakeEngine{ids: []string{"job-bound"}}
	run.CallbackSecretRef = "baiyan-primary"
	svc.repo.(*fakeRepo).runs[run.ProjectID][run.ID].CallbackSecretRef = run.CallbackSecretRef
	_, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "alice"})
	require.NoError(t, err)

	raw := validCallbackRaw(t, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	input := signedCallbackInput(1, run.ID, 1, now, "secret", raw)
	input.SecretRef = "baiyan-secondary"
	_, err = svc.HandleCallback(context.Background(), input)
	assert.ErrorIs(t, err, ErrInvalidCallbackSignature)
}
