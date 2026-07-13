//revive:disable:exported

package discovery

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
)

type PendingCallbackRecoverer interface {
	RecoverPendingCallbacks(ctx context.Context, limit int32) (int, error)
}

type RecoverCallbacksPayload struct {
	Limit int32 `json:"limit"`
}

type RecoverCallbacksHandler struct {
	recoverer PendingCallbackRecoverer
	logger    *slog.Logger
}

func NewRecoverCallbacksHandler(recoverer PendingCallbackRecoverer, logger *slog.Logger) *RecoverCallbacksHandler {
	return &RecoverCallbacksHandler{recoverer: recoverer, logger: logger}
}

func (h *RecoverCallbacksHandler) Register(mux *asynq.ServeMux) {
	mux.HandleFunc(TaskTypeRecoverCallbacks, h.Handle)
}

func (h *RecoverCallbacksHandler) Handle(ctx context.Context, task *asynq.Task) error {
	payload := RecoverCallbacksPayload{Limit: 100}
	if len(task.Payload()) > 0 {
		if err := json.Unmarshal(task.Payload(), &payload); err != nil {
			return err
		}
	}
	recovered, err := h.recoverer.RecoverPendingCallbacks(ctx, payload.Limit)
	if h.logger != nil {
		h.logger.Info("discovery callback recovery finished", "recovered", recovered, "failed", err != nil)
	}
	return err
}

type PeriodicTaskRegistrar interface {
	Register(cronspec string, task *asynq.Task, opts ...asynq.Option) (string, error)
}

// RegisterPeriodicTasks makes inbox recovery and timeout reconciliation
// observable and testable without starting a real Redis scheduler.
func RegisterPeriodicTasks(registrar PeriodicTaskRegistrar, queue string) ([]string, error) {
	if queue == "" {
		queue = "default"
	}
	recoveryBody, err := json.Marshal(RecoverCallbacksPayload{Limit: 100})
	if err != nil {
		return nil, err
	}
	reconcileBody, err := json.Marshal(ReconcileTimedOutRunsPayload{Limit: 100, ActorID: "scheduler"})
	if err != nil {
		return nil, err
	}
	entries := make([]string, 0, 2)
	entry, err := registrar.Register("@every 30s", asynq.NewTask(TaskTypeRecoverCallbacks, recoveryBody),
		asynq.Queue(queue), asynq.MaxRetry(5), asynq.Timeout(30*time.Second))
	if err != nil {
		return nil, err
	}
	entries = append(entries, entry)
	entry, err = registrar.Register("@every 1m", asynq.NewTask(TaskTypeReconcileTimedOutRun, reconcileBody),
		asynq.Queue(queue), asynq.MaxRetry(5), asynq.Timeout(45*time.Second))
	if err != nil {
		return nil, err
	}
	entries = append(entries, entry)
	return entries, nil
}
