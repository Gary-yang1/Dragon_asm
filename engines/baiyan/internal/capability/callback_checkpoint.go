package capability

import (
	"context"
	"errors"
	"strconv"

	"baiyan/internal/contract"
	"baiyan/internal/job"
)

// CheckpointedBatchSender persists callback progress around network delivery so
// a restarted engine skips acknowledged batches and replays an uncertain batch
// with its original payload.
type CheckpointedBatchSender struct {
	store  job.CallbackCheckpointStore
	sender BatchSender
}

// NewCheckpointedBatchSender binds callback delivery to the durable job store.
func NewCheckpointedBatchSender(store job.CallbackCheckpointStore, sender BatchSender) (*CheckpointedBatchSender, error) {
	if store == nil || sender == nil {
		return nil, errors.New("baiyan callback checkpoint: store and sender are required")
	}
	return &CheckpointedBatchSender{store: store, sender: sender}, nil
}

func (s *CheckpointedBatchSender) Send(ctx context.Context, callbackURL string, batch contract.CallbackBatch, retryLimit int) error {
	checkpoint, acknowledged, err := s.store.PrepareCallback(batch.RunID, batch)
	if err != nil {
		return err
	}
	if acknowledged {
		return nil
	}
	if err := s.sender.Send(ctx, callbackURL, checkpoint, retryLimit); err != nil {
		return err
	}
	return s.store.AcknowledgeCallback(batch.RunID, checkpoint.Seq)
}

// ResumeStream replays the uncertain batch verbatim before allocating fresh
// sequence numbers. Source completion order may change after a restart; never
// discard newly collected data by reusing old acknowledged sequence numbers.
func (s *CheckpointedBatchSender) ResumeStream(ctx context.Context, request contract.ScanRequest) (uint64, uint64, *job.ExecutionResult, error) {
	store, ok := s.store.(job.Store)
	if !ok {
		return 1, 0, nil, errors.New("stream checkpoint store cannot read job")
	}
	record, err := store.Get("job-" + strconv.FormatUint(request.RunID, 10))
	if err != nil {
		return 0, 0, nil, err
	}
	if record.PendingCallback != nil {
		if err := s.Send(ctx, request.CallbackURL, *record.PendingCallback, 3); err != nil {
			return 0, 0, nil, err
		}
		record, err = store.Get(record.JobID)
		if err != nil {
			return 0, 0, nil, err
		}
	}
	if record.LastCallbackStatus == job.StatusSuccess || record.LastCallbackStatus == job.StatusPartialSuccess || record.LastCallbackStatus == job.StatusFailed || record.LastCallbackStatus == job.StatusCancelled {
		return 0, record.CallbackResultCount, &job.ExecutionResult{Status: record.LastCallbackStatus, ResultCount: record.CallbackResultCount, ErrorSummary: record.LastCallbackSummary}, nil
	}
	return record.LastCallbackSeq + 1, record.CallbackResultCount, nil, nil
}
