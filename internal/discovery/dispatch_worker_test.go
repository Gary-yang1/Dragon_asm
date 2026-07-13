package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAsynqEnqueueClient struct {
	task *asynq.Task
	opts []asynq.Option
	err  error
}

func (f *fakeAsynqEnqueueClient) EnqueueContext(_ context.Context, task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	f.task = task
	f.opts = opts
	return nil, f.err
}

type fakeDispatchRunner struct {
	input DispatchTaskRunInput
	run   *TaskRun
	err   error
}

func (f *fakeDispatchRunner) DispatchTaskRun(_ context.Context, in DispatchTaskRunInput) (*TaskRun, error) {
	f.input = in
	return f.run, f.err
}

func TestCallbackURLBuilderUsesFixedPathAndTrustedIDs(t *testing.T) {
	builder, err := NewCallbackURLBuilder("https://asm.example.com")
	require.NoError(t, err)
	got, err := builder.Build(7, 123)
	require.NoError(t, err)
	assert.Equal(t, "https://asm.example.com/api/v1/discovery/callback?project_id=7&run_id=123", got)

	for _, invalid := range []string{"", "file:///tmp/callback", "https://user@asm.example.com", "https://asm.example.com/custom", "https://asm.example.com?x=1"} {
		_, err := NewCallbackURLBuilder(invalid)
		assert.ErrorIs(t, err, ErrCallbackURLConfig)
	}
}

func TestAsynqDispatchEnqueuerUsesIdentifiersOnlyAndStableTaskID(t *testing.T) {
	client := &fakeAsynqEnqueueClient{}
	enqueuer := NewAsynqDispatchEnqueuer(client, "critical")
	payload := DispatchTaskPayload{ProjectID: 7, RunID: 123, ActorID: "42"}
	require.NoError(t, enqueuer.EnqueueTaskRun(context.Background(), payload))
	require.NotNil(t, client.task)
	assert.Equal(t, TaskTypeDispatchTaskRun, client.task.Type())
	var decoded DispatchTaskPayload
	require.NoError(t, json.Unmarshal(client.task.Payload(), &decoded))
	assert.Equal(t, payload, decoded)

	values := map[asynq.OptionType]any{}
	for _, option := range client.opts {
		values[option.Type()] = option.Value()
	}
	assert.Equal(t, "critical", values[asynq.QueueOpt])
	assert.Equal(t, "dispatch:7:123", values[asynq.TaskIDOpt])
}

func TestAsynqDispatchEnqueuerTreatsTaskIDConflictAsSuccess(t *testing.T) {
	client := &fakeAsynqEnqueueClient{err: asynq.ErrTaskIDConflict}
	err := NewAsynqDispatchEnqueuer(client, "").EnqueueTaskRun(context.Background(), DispatchTaskPayload{
		ProjectID: 1, RunID: 2, ActorID: "3",
	})
	require.NoError(t, err)
}

func TestAsynqCallbackEnqueuerUsesIdentifiersOnlyAndStableTaskID(t *testing.T) {
	client := &fakeAsynqEnqueueClient{}
	enqueuer := NewAsynqCallbackEnqueuer(client, "critical")
	require.NoError(t, enqueuer.EnqueueDiscoveryCallback(context.Background(), DiscoveryCallback{
		ProjectID: 7, RunID: 123, Seq: 4, Payload: []byte(`{"secret":"must-not-enter-redis"}`),
	}))
	require.NotNil(t, client.task)
	assert.Equal(t, TaskTypeIngestScanResult, client.task.Type())
	assert.JSONEq(t, `{"project_id":7,"run_id":123,"seq":4}`, string(client.task.Payload()))
	assert.NotContains(t, string(client.task.Payload()), "must-not-enter-redis")
	values := map[asynq.OptionType]any{}
	for _, option := range client.opts {
		values[option.Type()] = option.Value()
	}
	assert.Equal(t, "critical", values[asynq.QueueOpt])
	assert.Equal(t, "ingest:7:123:4", values[asynq.TaskIDOpt])
}

func TestDispatchHandlerBuildsCallbackAndRunsService(t *testing.T) {
	builder, err := NewCallbackURLBuilder("https://asm.example.com")
	require.NoError(t, err)
	runner := &fakeDispatchRunner{run: &TaskRun{ID: 8, EngineJobID: "job-8"}}
	handler := NewDispatchHandler(runner, builder, nil)
	body, err := json.Marshal(DispatchTaskPayload{ProjectID: 4, RunID: 8, ActorID: "9"})
	require.NoError(t, err)

	err = handler.Handle(context.Background(), asynq.NewTask(TaskTypeDispatchTaskRun, body))
	require.NoError(t, err)
	assert.Equal(t, uint64(4), runner.input.ProjectID)
	assert.Equal(t, uint64(8), runner.input.RunID)
	assert.Equal(t, "9", runner.input.ActorID)
	assert.Equal(t, "https://asm.example.com/api/v1/discovery/callback?project_id=4&run_id=8", runner.input.CallbackURL)
}

func TestDispatchHandlerFailsClosedWithoutConfiguration(t *testing.T) {
	handler := NewDispatchHandler(&fakeDispatchRunner{}, nil, nil)
	body := []byte(`{"project_id":1,"run_id":2,"actor_id":"3"}`)
	err := handler.Handle(context.Background(), asynq.NewTask(TaskTypeDispatchTaskRun, body))
	assert.ErrorIs(t, err, ErrCallbackURLConfig)
}

func TestCreateAndEnqueueTaskRunAndQueueFailureClosure(t *testing.T) {
	svc, template, _ := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	enqueuer := &fakeTaskRunEnqueuer{}
	svc.dispatchEnqueuer = enqueuer
	run, err := svc.CreateAndEnqueueTaskRun(context.Background(), CreateTaskRunInput{
		ProjectID: 1, TemplateID: template.ID, ActorID: "alice",
	})
	require.NoError(t, err)
	require.Len(t, enqueuer.payloads, 1)
	assert.Equal(t, run.ID, enqueuer.payloads[0].RunID)
	assert.Equal(t, TaskRunStatusPending, run.Status)

	enqueuer.err = errors.New("redis unavailable")
	failed, err := svc.CreateAndEnqueueTaskRun(context.Background(), CreateTaskRunInput{
		ProjectID: 1, TemplateID: template.ID, ActorID: "alice",
	})
	assert.ErrorIs(t, err, ErrDispatchEnqueue)
	require.NotNil(t, failed)
	assert.Equal(t, TaskRunStatusCancelled, failed.Status)
	assert.Equal(t, "dispatch queue unavailable", failed.ErrorSummary)
}

func TestDispatchTaskRunIsIdempotentAfterEngineJobRecorded(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	engine := &fakeEngine{ids: []string{"job-idempotent"}}
	svc.engine = engine
	first, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1, RunID: run.ID, ActorID: "alice", CallbackURL: "https://asm.example.com/callback",
	})
	require.NoError(t, err)
	second, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1, RunID: run.ID, ActorID: "alice", CallbackURL: "https://asm.example.com/callback",
	})
	require.NoError(t, err)
	assert.Equal(t, first.EngineJobID, second.EngineJobID)
	assert.Equal(t, 1, engine.dispatchCalls)
}
