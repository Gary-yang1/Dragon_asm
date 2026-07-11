//revive:disable:exported

package discovery

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/hibiken/asynq"
)

type TimeoutReconciler interface {
	ReconcileTimedOutRuns(ctx context.Context, in ReconcileTimedOutRunsInput) (ReconcileTimedOutRunsResult, error)
}

type ReconcileTimedOutRunsPayload struct {
	Limit   int32  `json:"limit"`
	ActorID string `json:"actor_id"`
}

type ReconcileHandler struct {
	reconciler TimeoutReconciler
	logger     *slog.Logger
}

func NewReconcileHandler(reconciler TimeoutReconciler, logger *slog.Logger) *ReconcileHandler {
	return &ReconcileHandler{reconciler: reconciler, logger: logger}
}

func (h *ReconcileHandler) Register(mux *asynq.ServeMux) {
	mux.HandleFunc(TaskTypeReconcileTimedOutRun, h.Handle)
}

func (h *ReconcileHandler) Handle(ctx context.Context, task *asynq.Task) error {
	var payload ReconcileTimedOutRunsPayload
	if len(task.Payload()) > 0 {
		if err := json.Unmarshal(task.Payload(), &payload); err != nil {
			return err
		}
	}
	if payload.ActorID == "" {
		payload.ActorID = "system"
	}
	result, err := h.reconciler.ReconcileTimedOutRuns(ctx, ReconcileTimedOutRunsInput{
		Limit:   payload.Limit,
		ActorID: payload.ActorID,
	})
	if h.logger != nil {
		h.logger.Info("discovery timeout reconcile finished",
			"checked", result.Checked,
			"updated", result.Updated,
			"cancelled", result.Cancelled,
			"errors", len(result.Errors),
		)
	}
	return err
}
