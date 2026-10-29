//revive:disable:exported

package discovery

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/hibiken/asynq"
)

type RunningRunsReconciler interface {
	ReconcileRunningRuns(ctx context.Context, in ReconcileRunningRunsInput) (ReconcileTimedOutRunsResult, error)
}

type ReconcileRunningRunsPayload struct {
	Limit   int32  `json:"limit"`
	ActorID string `json:"actor_id"`
}

type ReconcileTimedOutRunsPayload = ReconcileRunningRunsPayload

type ReconcileHandler struct {
	reconciler RunningRunsReconciler
	logger     *slog.Logger
}

func NewReconcileHandler(reconciler RunningRunsReconciler, logger *slog.Logger) *ReconcileHandler {
	return &ReconcileHandler{reconciler: reconciler, logger: logger}
}

func (h *ReconcileHandler) Register(mux *asynq.ServeMux) {
	mux.HandleFunc(TaskTypeReconcileRunningRuns, h.Handle)
	// Keep draining tasks queued by the pre-MA-7 scheduler. Their payload is
	// compatible, and normal polling includes timeout recovery.
	mux.HandleFunc(TaskTypeReconcileTimedOutRun, h.Handle)
}

func (h *ReconcileHandler) Handle(ctx context.Context, task *asynq.Task) error {
	var payload ReconcileRunningRunsPayload
	if len(task.Payload()) > 0 {
		if err := json.Unmarshal(task.Payload(), &payload); err != nil {
			return err
		}
	}
	if payload.ActorID == "" {
		payload.ActorID = "system"
	}
	result, err := h.reconciler.ReconcileRunningRuns(ctx, ReconcileRunningRunsInput{
		Limit:   payload.Limit,
		ActorID: payload.ActorID,
	})
	if h.logger != nil {
		h.logger.Info("discovery running-run reconcile finished",
			"checked", result.Checked,
			"updated", result.Updated,
			"cancelled", result.Cancelled,
			"errors", len(result.Errors),
			"failed_run_ids", result.FailedRunIDs,
		)
	}
	return err
}
