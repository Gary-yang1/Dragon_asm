package job

import (
	"context"
	"time"

	"baiyan/internal/contract"
)

const (
	StatusQueued         = "queued"
	StatusRunning        = "running"
	StatusSuccess        = "success"
	StatusPartialSuccess = "partial_success"
	StatusFailed         = "failed"
	StatusCancelled      = "cancelled"
)

type Record struct {
	JobID           string                  `json:"job_id"`
	IdempotencyKey  string                  `json:"idempotency_key"`
	RequestHash     string                  `json:"request_hash"`
	Request         contract.ScanRequest    `json:"request"`
	Status          string                  `json:"status"`
	Progress        int                     `json:"progress"`
	ResultCount     uint64                  `json:"result_count"`
	ErrorSummary    string                  `json:"error_summary"`
	LastCallbackSeq uint64                  `json:"last_callback_seq,omitempty"`
	PendingCallback *contract.CallbackBatch `json:"pending_callback,omitempty"`
	CreatedAt       time.Time               `json:"created_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
}

type ExecutionResult struct {
	Status       string
	ResultCount  uint64
	ErrorSummary string
}

type Executor interface {
	Execute(ctx context.Context, request contract.ScanRequest) (ExecutionResult, error)
}

func (r *Record) PublicStatus() contract.JobStatus {
	return contract.JobStatus{
		SchemaVersion: contract.SchemaVersion, JobID: r.JobID, RunID: r.Request.RunID,
		Status: r.Status, Progress: r.Progress, ResultCount: r.ResultCount,
		ErrorSummary: r.ErrorSummary, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}
