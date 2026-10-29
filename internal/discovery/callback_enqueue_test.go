package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/require"
)

type countingEnqueueClient struct {
	errs  []error
	calls int
}

func (c *countingEnqueueClient) EnqueueContext(context.Context, *asynq.Task, ...asynq.Option) (*asynq.TaskInfo, error) {
	err := c.errs[min(c.calls, len(c.errs)-1)]
	c.calls++
	return nil, err
}

type recordingTaskRunner struct {
	queue, id string
	err       error
	calls     int
}

func (r *recordingTaskRunner) RunTask(queue, id string) error {
	r.queue, r.id = queue, id
	r.calls++
	return r.err
}

var stuckCallback = DiscoveryCallback{ProjectID: 7, RunID: 21, Seq: 2}

// Run 21 on the test environment: recovery released 34 abandoned claims, but
// their old tasks were in retry backoff, so the enqueue hit a TaskID conflict
// and did nothing; the callbacks waited out an hours-long backoff.
func TestRecoveryEnqueueRunsAnExistingTaskInsteadOfDroppingIt(t *testing.T) {
	client := &countingEnqueueClient{errs: []error{asynq.ErrTaskIDConflict}}
	runner := &recordingTaskRunner{}
	enqueuer := NewAsynqCallbackEnqueuer(client, "default").WithTaskRunner(runner)
	require.NoError(t, enqueuer.EnqueueDiscoveryCallback(context.Background(), stuckCallback))
	require.Equal(t, 1, runner.calls)
	require.Equal(t, "default", runner.queue)
	require.Equal(t, "ingest:7:21:2", runner.id)
	require.Equal(t, 1, client.calls)
}

func TestRecoveryEnqueueReenqueuesWhenTheOldTaskIsGone(t *testing.T) {
	client := &countingEnqueueClient{errs: []error{asynq.ErrTaskIDConflict, nil}}
	runner := &recordingTaskRunner{err: errors.Join(errors.New("asynq"), asynq.ErrTaskNotFound)}
	enqueuer := NewAsynqCallbackEnqueuer(client, "default").WithTaskRunner(runner)
	require.NoError(t, enqueuer.EnqueueDiscoveryCallback(context.Background(), stuckCallback))
	require.Equal(t, 2, client.calls, "a vanished task is enqueued again")
}

func TestRecoveryEnqueueAcceptsATaskAlreadyPendingOrActive(t *testing.T) {
	client := &countingEnqueueClient{errs: []error{asynq.ErrTaskIDConflict}}
	runner := &recordingTaskRunner{err: errors.New("asynq: task is already running")}
	enqueuer := NewAsynqCallbackEnqueuer(client, "default").WithTaskRunner(runner)
	require.NoError(t, enqueuer.EnqueueDiscoveryCallback(context.Background(), stuckCallback))
	require.Equal(t, 1, client.calls)
}

func TestEnqueueWithoutRunnerKeepsTheConflictNoOp(t *testing.T) {
	client := &countingEnqueueClient{errs: []error{asynq.ErrTaskIDConflict}}
	require.NoError(t, NewAsynqCallbackEnqueuer(client, "default").EnqueueDiscoveryCallback(context.Background(), stuckCallback))
	require.Equal(t, 1, client.calls)
}
