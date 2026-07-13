//revive:disable:exported

package discovery

import (
	"context"
	"errors"
	"time"
)

var (
	ErrEngineNotConfigured = errors.New("discovery: engine adapter not configured")
	ErrEngineDispatch      = errors.New("discovery: engine dispatch failed")
	ErrEngineCancel        = errors.New("discovery: engine cancel failed")
	ErrEngineStatus        = errors.New("discovery: engine status failed")
	ErrCallbackURLConfig   = errors.New("discovery: callback base url not configured")
)

// Target is the engine-facing target shape. Values must already be authorized.
type Target struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ScanJob is the request passed to the engine adapter.
type ScanJob struct {
	RunID       uint64         `json:"run_id"`
	ProjectID   uint64         `json:"project_id"`
	ScopeID     uint64         `json:"scope_id"`
	JobType     string         `json:"job_type"`
	Targets     []Target       `json:"targets"`
	RateLimit   int            `json:"rate_limit"`
	Concurrency int            `json:"concurrency"`
	Timeout     time.Duration  `json:"-"`
	CallbackURL string         `json:"callback_url,omitempty"`
	Options     map[string]any `json:"options,omitempty"`
}

// Engine job statuses returned by GET /scan/{id}.
const (
	EngineJobStatusRunning        = "running"
	EngineJobStatusSuccess        = "success"
	EngineJobStatusPartialSuccess = "partial_success"
	EngineJobStatusFailed         = "failed"
	EngineJobStatusCancelled      = "cancelled"
)

// EngineJobStatus is the normalized status snapshot returned by the engine.
type EngineJobStatus struct {
	Status       string
	Progress     int
	ResultCount  uint64
	ErrorSummary string
}

// EngineAdapter dispatches and cancels external engine jobs.
type EngineAdapter interface {
	Dispatch(ctx context.Context, job ScanJob) (engineJobID string, err error)
	Cancel(ctx context.Context, engineJobID string) error
	Status(ctx context.Context, engineJobID string) (EngineJobStatus, error)
}

// DispatchTaskRunInput requests an engine dispatch for one pending run.
type DispatchTaskRunInput struct {
	ProjectID   uint64
	RunID       uint64
	ActorID     string
	CallbackURL string
	Meta        AuditMeta
}

// ReconcileTaskRunInput requests active engine status reconciliation for one run.
type ReconcileTaskRunInput struct {
	ProjectID uint64
	RunID     uint64
	ActorID   string
	Meta      AuditMeta
}

// ReconcileTimedOutRunsInput requests batch timeout recovery for running runs.
type ReconcileTimedOutRunsInput struct {
	Limit   int32
	ActorID string
	Meta    AuditMeta
}

// ReconcileTimedOutRunsResult summarizes one timeout recovery pass.
type ReconcileTimedOutRunsResult struct {
	Checked   int
	Updated   int
	Cancelled int
	Errors    []error
}
