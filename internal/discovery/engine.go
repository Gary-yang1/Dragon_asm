//revive:disable:exported

package discovery

import (
	"context"
	"errors"
	"fmt"
	"github.com/Gary-yang1/Dragon_asm/internal/webview"
	"time"
)

var (
	ErrEngineNotConfigured     = errors.New("discovery: engine adapter not configured")
	ErrEngineDispatch          = errors.New("discovery: engine dispatch failed")
	ErrEngineCancel            = errors.New("discovery: engine cancel failed")
	ErrEngineStatus            = errors.New("discovery: engine status failed")
	ErrEngineResult            = errors.New("discovery: engine result failed")
	ErrEngineResultUnsupported = fmt.Errorf(
		"%w: engine does not expose paged results",
		ErrEngineResult,
	)
	ErrEngineResultIncomplete = fmt.Errorf(
		"%w: terminal engine result is incomplete",
		ErrEngineResult,
	)

	// ErrEngineJobRejected marks a dispatch the adapter itself refuses: an
	// unsupported job type, or a payload missing required identifiers. It wraps
	// ErrEngineDispatch so existing handling still matches, but lets the dispatcher
	// recognise a failure that no number of retries can fix. This also protects
	// historical rows created before task capability and config validation moved
	// to the public template boundary.
	ErrEngineJobRejected = fmt.Errorf("%w: job rejected before dispatch", ErrEngineDispatch)
	ErrCallbackURLConfig = errors.New("discovery: callback base url not configured")
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

// EnginePortResult is one active port-scan target result. Ports retains the
// provider's compact representation and is parsed by the normalization layer.
type EnginePortResult struct {
	Target string
	Ports  string
}

// EngineWebFingerprint is the non-sensitive fingerprint subset ASM persists.
type EngineWebFingerprint struct {
	Name       string
	StatusCode string
	Title      string
}

// EngineWebResult is one active Web/fingerprint target result. Deliberately no
// PoC request, response, exchange, cookie, or header fields cross this boundary.
type EngineWebResult struct {
	Web          *webview.Observation
	Target       string
	Port         int
	Fingerprints []EngineWebFingerprint
}

// EngineResultPage is one bounded provider page. Exactly one result slice is
// populated according to the TaskRun task type.
type EngineResultPage struct {
	TaskID          string
	Page            int
	PageSize        int
	TotalTargets    int
	FinishedTargets int
	PortResults     []EnginePortResult
	WebResults      []EngineWebResult
}

// EngineResultFetcher is implemented only by engines with a pull-based result
// contract. Keeping it separate preserves callback-only engine compatibility.
type EngineResultFetcher interface {
	FetchResultPage(
		ctx context.Context,
		engineJobID string,
		taskType string,
		page int,
		pageSize int,
	) (EngineResultPage, error)
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

// ReconcileRunningRunsInput requests normal status/result polling for active
// running jobs. Timeout recovery remains part of the same pass.
type ReconcileRunningRunsInput struct {
	Limit   int32
	ActorID string
	Meta    AuditMeta
}

// ReconcileTimedOutRunsResult summarizes one timeout recovery pass.
type ReconcileTimedOutRunsResult struct {
	Checked      int
	Updated      int
	Cancelled    int
	FailedRunIDs []uint64
	Errors       []error
}
