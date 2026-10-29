//revive:disable:exported

package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hibiken/asynq"
)

const (
	TaskTypeIngestScanResult     = "ingest_scan_result"
	TaskTypeReconcileTimedOutRun = "reconcile_timed_out_runs"
	TaskTypeReconcileRunningRuns = "reconcile_running_runs"
	TaskTypeDispatchTaskRun      = "dispatch_task_run"
	TaskTypeRecoverCallbacks     = "recover_discovery_callbacks"
)

var ErrDispatchEnqueue = errors.New("discovery: task run enqueue failed")

// DispatchTaskPayload contains identifiers only. Callback origins, engine
// credentials, targets, and options are resolved from trusted server state.
type DispatchTaskPayload struct {
	ProjectID uint64 `json:"project_id"`
	RunID     uint64 `json:"run_id"`
	ActorID   string `json:"actor_id"`
}

// DispatchEnqueuer persists a TaskRun dispatch request in the worker queue.
type DispatchEnqueuer interface {
	EnqueueTaskRun(ctx context.Context, payload DispatchTaskPayload) error
}

type asynqEnqueueClient interface {
	EnqueueContext(ctx context.Context, task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error)
}

// AsynqDispatchEnqueuer uses a deterministic TaskID so repeated submissions of
// the same project/run pair are idempotent at the queue boundary.
type AsynqDispatchEnqueuer struct {
	client asynqEnqueueClient
	queue  string
}

func NewAsynqDispatchEnqueuer(client asynqEnqueueClient, queue string) *AsynqDispatchEnqueuer {
	if queue == "" {
		queue = "default"
	}
	return &AsynqDispatchEnqueuer{client: client, queue: queue}
}

func (e *AsynqDispatchEnqueuer) EnqueueTaskRun(ctx context.Context, payload DispatchTaskPayload) error {
	if e == nil || e.client == nil || payload.ProjectID == 0 || payload.RunID == 0 || payload.ActorID == "" {
		return ErrDispatchEnqueue
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.Join(ErrDispatchEnqueue, err)
	}
	taskID := fmt.Sprintf("dispatch:%d:%d", payload.ProjectID, payload.RunID)
	task := asynq.NewTask(TaskTypeDispatchTaskRun, body)
	_, err = e.client.EnqueueContext(ctx, task, asynq.Queue(e.queue), asynq.TaskID(taskID))
	if errors.Is(err, asynq.ErrTaskIDConflict) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrDispatchEnqueue, err)
	}
	return nil
}

// CallbackTaskPayload is the worker payload for an accepted callback batch.
type CallbackTaskPayload struct {
	ProjectID uint64 `json:"project_id"`
	RunID     uint64 `json:"run_id"`
	Seq       uint64 `json:"seq"`
}

// asynqTaskRunner moves an existing task to the pending queue now
// (asynq.Inspector satisfies it).
type asynqTaskRunner interface {
	RunTask(queue, id string) error
}

// AsynqCallbackEnqueuer pushes callback batches to the worker queue.
type AsynqCallbackEnqueuer struct {
	client asynqEnqueueClient
	queue  string
	runner asynqTaskRunner
}

// WithTaskRunner lets a re-enqueue of a callback whose task already exists run
// that task now. Without it, a task sitting in retry backoff or the archive
// kept the TaskID, so recovery's enqueue was a silent no-op and the callback
// waited out the backoff — hours, after a burst of busy retries.
func (e *AsynqCallbackEnqueuer) WithTaskRunner(runner asynqTaskRunner) *AsynqCallbackEnqueuer {
	e.runner = runner
	return e
}

func NewAsynqCallbackEnqueuer(client asynqEnqueueClient, queue string) *AsynqCallbackEnqueuer {
	if queue == "" {
		queue = "default"
	}
	return &AsynqCallbackEnqueuer{client: client, queue: queue}
}

func (e *AsynqCallbackEnqueuer) EnqueueDiscoveryCallback(ctx context.Context, cb DiscoveryCallback) error {
	if e == nil || e.client == nil || cb.ProjectID == 0 || cb.RunID == 0 || cb.Seq == 0 {
		return ErrCallbackEnqueue
	}
	payload, err := json.Marshal(CallbackTaskPayload{
		ProjectID: cb.ProjectID,
		RunID:     cb.RunID,
		Seq:       cb.Seq,
	})
	if err != nil {
		return errors.Join(ErrCallbackEnqueue, err)
	}
	task := asynq.NewTask(TaskTypeIngestScanResult, payload)
	taskID := fmt.Sprintf("ingest:%d:%d:%d", cb.ProjectID, cb.RunID, cb.Seq)
	_, err = e.client.EnqueueContext(ctx, task, asynq.Queue(e.queue), asynq.TaskID(taskID))
	if errors.Is(err, asynq.ErrTaskIDConflict) {
		if e.runner == nil {
			return nil
		}
		runErr := e.runner.RunTask(e.queue, taskID)
		if errors.Is(runErr, asynq.ErrTaskNotFound) {
			// The old task finished or was removed between the two calls.
			_, err = e.client.EnqueueContext(ctx, task, asynq.Queue(e.queue), asynq.TaskID(taskID))
			if errors.Is(err, asynq.ErrTaskIDConflict) {
				return nil
			}
		} else {
			// Any other outcome means the task is already pending or active,
			// which is what the enqueue wanted.
			return nil
		}
	}
	if err != nil {
		return errors.Join(ErrCallbackEnqueue, err)
	}
	return nil
}
