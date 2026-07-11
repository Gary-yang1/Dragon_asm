//revive:disable:exported

package report

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/hibiken/asynq"
)

const TaskTypeProcessExport = "report:export:process"

type ExportEnqueuer interface {
	EnqueueReportExport(ctx context.Context, projectID uint64) error
}

type AsynqExportEnqueuer struct {
	client *asynq.Client
	queue  string
}

func NewAsynqExportEnqueuer(client *asynq.Client, queue string) *AsynqExportEnqueuer {
	if queue == "" {
		queue = "low"
	}
	return &AsynqExportEnqueuer{client: client, queue: queue}
}

func (e *AsynqExportEnqueuer) EnqueueReportExport(ctx context.Context, projectID uint64) error {
	task, err := NewProcessExportTask(projectID)
	if err != nil {
		return err
	}
	_, err = e.client.EnqueueContext(ctx, task, asynq.Queue(e.queue))
	return err
}

type ExportHandler struct {
	svc    *Service
	logger *slog.Logger
}

func NewExportHandler(svc *Service, logger *slog.Logger) *ExportHandler {
	return &ExportHandler{svc: svc, logger: logger}
}

func (h *ExportHandler) Register(mux *asynq.ServeMux) {
	mux.HandleFunc(TaskTypeProcessExport, h.Handle)
}

func (h *ExportHandler) Handle(ctx context.Context, task *asynq.Task) error {
	var payload struct {
		ProjectID uint64 `json:"project_id,omitempty"`
	}
	if len(task.Payload()) > 0 {
		_ = json.Unmarshal(task.Payload(), &payload)
	}
	job, err := h.svc.ProcessNextExport(ctx)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if h.logger != nil {
		h.logger.Info("report export completed", "project_id", job.ProjectID, "export_id", job.ID, "rows", job.RowCount)
	}
	return nil
}

func NewProcessExportTask(projectID uint64) (*asynq.Task, error) {
	payload, err := json.Marshal(struct {
		ProjectID uint64 `json:"project_id,omitempty"`
	}{ProjectID: projectID})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeProcessExport, payload), nil
}
