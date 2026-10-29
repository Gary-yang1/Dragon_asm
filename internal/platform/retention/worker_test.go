package retention_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/retention"
)

type fakeRunner struct {
	calls  []retention.Policy
	stats  retention.Stats
	err    error
	called int
}

func (f *fakeRunner) Run(_ context.Context, policy retention.Policy) (retention.Stats, error) {
	f.called++
	f.calls = append(f.calls, policy)
	return f.stats, f.err
}

type fakeRegistrar struct {
	specs  []string
	queues []asynq.Option
	types  []string
	err    error
}

func (f *fakeRegistrar) Register(cronspec string, task *asynq.Task, opts ...asynq.Option) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.specs = append(f.specs, cronspec)
	f.types = append(f.types, task.Type())
	f.queues = append(f.queues, opts...)
	return "entry-" + cronspec, nil
}

func TestHandlerRunsWithDefaultPolicyOnEmptyPayload(t *testing.T) {
	runner := &fakeRunner{stats: retention.Stats{AuditLogsArchived: 5, AuditLogsDeleted: 3}}
	handler := retention.NewHandler(runner, nil)
	mux := asynq.NewServeMux()
	handler.Register(mux)

	err := mux.ProcessTask(context.Background(), asynq.NewTask(retention.TaskTypeRunRetention, nil))
	require.NoError(t, err)
	require.Equal(t, 1, runner.called)
	assert.Equal(t, retention.DefaultPolicy(), runner.calls[0])
}

func TestHandlerAppliesPayloadOverrides(t *testing.T) {
	runner := &fakeRunner{}
	handler := retention.NewHandler(runner, nil)

	body, err := json.Marshal(retention.RunRetentionPayload{BatchSize: 42, ActorID: "operator-1"})
	require.NoError(t, err)

	mux := asynq.NewServeMux()
	handler.Register(mux)
	require.NoError(t, mux.ProcessTask(context.Background(), asynq.NewTask(retention.TaskTypeRunRetention, body)))

	require.Len(t, runner.calls, 1)
	assert.Equal(t, 42, runner.calls[0].BatchSize)
	assert.Equal(t, "operator-1", runner.calls[0].ActorID)
	// Unspecified fields keep the default policy rather than becoming zero, which
	// would otherwise mean "archive everything immediately".
	assert.Equal(t, retention.DefaultPolicy().AuditMinRetentionDays, runner.calls[0].AuditMinRetentionDays)
}

func TestHandlerPropagatesFailure(t *testing.T) {
	wantErr := errors.New("archive failed")
	handler := retention.NewHandler(&fakeRunner{err: wantErr}, nil)
	mux := asynq.NewServeMux()
	handler.Register(mux)

	err := mux.ProcessTask(context.Background(), asynq.NewTask(retention.TaskTypeRunRetention, nil))
	assert.ErrorIs(t, err, wantErr, "a failed run must be retried by the queue, not swallowed")
}

func TestRegisterPeriodicTasksSchedulesNightlyRun(t *testing.T) {
	registrar := &fakeRegistrar{}
	entries, err := retention.RegisterPeriodicTasks(registrar, "low")
	require.NoError(t, err)

	require.Len(t, entries, 1)
	require.Len(t, registrar.specs, 1)
	assert.Equal(t, "0 3 * * *", registrar.specs[0], "the prune scans the largest tables; keep it in a quiet window")
	assert.Equal(t, retention.TaskTypeRunRetention, registrar.types[0])
}

func TestRegisterPeriodicTasksSurfacesRegistrationFailure(t *testing.T) {
	wantErr := errors.New("scheduler down")
	_, err := retention.RegisterPeriodicTasks(&fakeRegistrar{err: wantErr}, "low")
	assert.ErrorIs(t, err, wantErr)
}
