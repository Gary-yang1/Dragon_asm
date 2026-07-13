//revive:disable:exported

package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	"github.com/hibiken/asynq"
)

// CallbackURLBuilder builds engine callback URLs from one trusted origin.
// User input is never accepted and the path is always replaced with the fixed
// ASM v1 callback route.
type CallbackURLBuilder struct {
	origin url.URL
}

func NewCallbackURLBuilder(rawBaseURL string) (*CallbackURLBuilder, error) {
	rawBaseURL = strings.TrimSpace(rawBaseURL)
	if rawBaseURL == "" {
		return nil, ErrCallbackURLConfig
	}
	u, err := url.Parse(rawBaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrCallbackURLConfig
	}
	u.Path = ""
	u.RawPath = ""
	return &CallbackURLBuilder{origin: *u}, nil
}

func (b *CallbackURLBuilder) Build(projectID, runID uint64) (string, error) {
	if b == nil || projectID == 0 || runID == 0 {
		return "", ErrCallbackURLConfig
	}
	u := b.origin
	u.Path = "/api/v1/discovery/callback"
	query := url.Values{}
	query.Set("project_id", strconv.FormatUint(projectID, 10))
	query.Set("run_id", strconv.FormatUint(runID, 10))
	u.RawQuery = query.Encode()
	return u.String(), nil
}

type dispatchTaskRunner interface {
	DispatchTaskRun(ctx context.Context, in DispatchTaskRunInput) (*TaskRun, error)
}

// DispatchHandler consumes dispatch_task_run jobs and invokes the existing
// authorization-aware dispatch service.
type DispatchHandler struct {
	runner   dispatchTaskRunner
	callback *CallbackURLBuilder
	logger   *slog.Logger
}

func NewDispatchHandler(runner dispatchTaskRunner, callback *CallbackURLBuilder, logger *slog.Logger) *DispatchHandler {
	return &DispatchHandler{runner: runner, callback: callback, logger: logger}
}

func (h *DispatchHandler) Register(mux *asynq.ServeMux) {
	mux.HandleFunc(TaskTypeDispatchTaskRun, h.Handle)
}

func (h *DispatchHandler) Handle(ctx context.Context, task *asynq.Task) error {
	if h == nil || h.runner == nil {
		return ErrEngineNotConfigured
	}
	var payload DispatchTaskPayload
	decoder := json.NewDecoder(bytes.NewReader(task.Payload()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.ProjectID == 0 || payload.RunID == 0 || strings.TrimSpace(payload.ActorID) == "" {
		return ErrDispatchEnqueue
	}
	callbackURL, err := h.callback.Build(payload.ProjectID, payload.RunID)
	if err != nil {
		return err
	}
	run, err := h.runner.DispatchTaskRun(ctx, DispatchTaskRunInput{
		ProjectID:   payload.ProjectID,
		RunID:       payload.RunID,
		ActorID:     payload.ActorID,
		CallbackURL: callbackURL,
	})
	if errors.Is(err, ErrTaskRunNotDispatchable) || errors.Is(err, ErrInvalidRunTransition) {
		return nil
	}
	if err != nil {
		return err
	}
	if h.logger != nil {
		h.logger.Info("discovery task run dispatched",
			"project_id", payload.ProjectID,
			"run_id", payload.RunID,
			"engine_job_id", run.EngineJobID,
		)
	}
	return nil
}
