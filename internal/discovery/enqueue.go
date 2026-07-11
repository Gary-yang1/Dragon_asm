//revive:disable:exported

package discovery

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hibiken/asynq"
)

const (
	TaskTypeIngestScanResult     = "ingest_scan_result"
	TaskTypeReconcileTimedOutRun = "reconcile_timed_out_runs"
)

// CallbackTaskPayload is the worker payload for an accepted callback batch.
type CallbackTaskPayload struct {
	Callback DiscoveryCallback `json:"callback"`
	RawBody  json.RawMessage   `json:"raw_body"`
}

// AsynqCallbackEnqueuer pushes callback batches to the worker queue.
type AsynqCallbackEnqueuer struct {
	client *asynq.Client
	queue  string
}

func NewAsynqCallbackEnqueuer(client *asynq.Client, queue string) *AsynqCallbackEnqueuer {
	if queue == "" {
		queue = "default"
	}
	return &AsynqCallbackEnqueuer{client: client, queue: queue}
}

func (e *AsynqCallbackEnqueuer) EnqueueDiscoveryCallback(ctx context.Context, cb DiscoveryCallback, rawBody []byte) error {
	if e == nil || e.client == nil {
		return errors.New("discovery: callback enqueuer not configured")
	}
	payload, err := json.Marshal(CallbackTaskPayload{
		Callback: cb,
		RawBody:  json.RawMessage(rawBody),
	})
	if err != nil {
		return err
	}
	task := asynq.NewTask(TaskTypeIngestScanResult, payload)
	_, err = e.client.EnqueueContext(ctx, task, asynq.Queue(e.queue))
	return err
}
