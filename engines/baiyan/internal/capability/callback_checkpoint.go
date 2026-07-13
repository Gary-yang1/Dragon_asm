package capability

import (
	"context"
	"errors"

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
