package retention

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
)

// TaskTypeRunRetention is the asynq task that archives and prunes cold rows.
const TaskTypeRunRetention = "retention:run"

// RunRetentionPayload lets an operator override the policy for a single run;
// zero fields fall back to DefaultPolicy.
type RunRetentionPayload struct {
	AuditMinRetentionDays       int    `json:"audit_min_retention_days,omitempty"`
	AuditArchiveAfterDays       int    `json:"audit_archive_after_days,omitempty"`
	ChangeEventArchiveAfterDays int    `json:"change_event_archive_after_days,omitempty"`
	DiscoveryCallbackAfterDays  int    `json:"discovery_callback_after_days,omitempty"`
	BatchSize                   int    `json:"batch_size,omitempty"`
	ActorID                     string `json:"actor_id,omitempty"`
}

func (p RunRetentionPayload) policy() Policy {
	base := DefaultPolicy()
	if p.AuditMinRetentionDays > 0 {
		base.AuditMinRetentionDays = p.AuditMinRetentionDays
	}
	if p.AuditArchiveAfterDays > 0 {
		base.AuditArchiveAfterDays = p.AuditArchiveAfterDays
	}
	if p.ChangeEventArchiveAfterDays > 0 {
		base.ChangeEventArchiveAfterDays = p.ChangeEventArchiveAfterDays
	}
	if p.DiscoveryCallbackAfterDays > 0 {
		base.DiscoveryCallbackAfterDays = p.DiscoveryCallbackAfterDays
	}
	if p.BatchSize > 0 {
		base.BatchSize = p.BatchSize
	}
	if p.ActorID != "" {
		base.ActorID = p.ActorID
	}
	return base
}

// Runner is the subset of Service the handler needs.
type Runner interface {
	Run(ctx context.Context, policy Policy) (Stats, error)
}

// Handler runs the retention policy from the worker queue.
//
// The service and its tests already existed but nothing scheduled them, so audit
// logs, change events, and callback payloads grew without bound — the tables the
// platform is least able to afford growing.
type Handler struct {
	svc    Runner
	logger *slog.Logger
}

// NewHandler builds the retention task handler.
func NewHandler(svc Runner, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, logger: logger}
}

// Register mounts the handler on the asynq mux.
func (h *Handler) Register(mux *asynq.ServeMux) {
	mux.HandleFunc(TaskTypeRunRetention, h.handle)
}

func (h *Handler) handle(ctx context.Context, task *asynq.Task) error {
	payload := RunRetentionPayload{}
	if raw := task.Payload(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
	}
	stats, err := h.svc.Run(ctx, payload.policy())
	if h.logger != nil {
		h.logger.Info("retention run finished",
			"audit_archived", stats.AuditLogsArchived, "audit_deleted", stats.AuditLogsDeleted,
			"change_events_archived", stats.ChangeEventsArchived, "change_events_deleted", stats.ChangeEventsDeleted,
			"callbacks_archived", stats.DiscoveryCallbacksArchived, "callbacks_deleted", stats.DiscoveryCallbacksDeleted,
			"failed", err != nil)
	}
	return err
}

// PeriodicTaskRegistrar is the scheduler subset used for registration.
type PeriodicTaskRegistrar interface {
	Register(cronspec string, task *asynq.Task, opts ...asynq.Option) (string, error)
}

// RegisterPeriodicTasks schedules the nightly retention run.
//
// It runs once a day at 03:00 rather than on a short interval: the job scans and
// deletes across the largest tables, so it belongs in a quiet window.
func RegisterPeriodicTasks(registrar PeriodicTaskRegistrar, queue string) ([]string, error) {
	if queue == "" {
		queue = "low"
	}
	body, err := json.Marshal(RunRetentionPayload{})
	if err != nil {
		return nil, err
	}
	entry, err := registrar.Register("0 3 * * *", asynq.NewTask(TaskTypeRunRetention, body),
		asynq.Queue(queue), asynq.MaxRetry(3), asynq.Timeout(30*time.Minute))
	if err != nil {
		return nil, err
	}
	return []string{entry}, nil
}
