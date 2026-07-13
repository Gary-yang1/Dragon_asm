//revive:disable:exported

package discovery

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrCallbackIngestBusy      = errors.New("discovery: callback ingest already in progress")
	ErrCallbackFinalSequence   = errors.New("discovery: callback final sequence is invalid")
	ErrCallbackFinalTransition = errors.New("discovery: callback final transition is invalid")
)

type CompleteCallbackIngestResult struct {
	Processed bool
	Finalized bool
}

func (s *Service) GetDiscoveryCallback(ctx context.Context, projectID, runID, seq uint64) (*DiscoveryCallback, error) {
	return s.repo.GetDiscoveryCallback(ctx, projectID, runID, seq)
}

// ClaimDiscoveryCallbackIngest acquires a callback for one worker attempt.
// Failed rows and stale processing claims are recoverable up to the SQL cap.
func (s *Service) ClaimDiscoveryCallbackIngest(ctx context.Context, projectID, runID, seq uint64) (bool, error) {
	return s.repo.MarkDiscoveryCallbackProcessing(ctx, projectID, runID, seq)
}

func (s *Service) FailDiscoveryCallbackIngest(ctx context.Context, projectID, runID, seq uint64) error {
	return s.repo.MarkDiscoveryCallbackFailed(ctx, projectID, runID, seq, "callback ingest failed")
}

// CompleteDiscoveryCallbackIngest atomically marks the inbox row processed,
// increments the run count once, and closes a legal final sequence only after
// every sequence through the final callback has been processed.
func (s *Service) CompleteDiscoveryCallbackIngest(ctx context.Context, projectID, runID, seq uint64) (CompleteCallbackIngestResult, error) {
	result := CompleteCallbackIngestResult{}
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		current, err := repo.GetDiscoveryCallback(ctx, projectID, runID, seq)
		if err != nil {
			return err
		}
		if current.IngestStatus == CallbackIngestProcessed {
			return nil
		}
		if current.IngestStatus != CallbackIngestProcessing {
			return ErrCallbackIngestBusy
		}
		processed, err := repo.MarkDiscoveryCallbackProcessed(ctx, projectID, runID, seq, s.nowFn())
		if err != nil {
			return err
		}
		if !processed {
			return ErrCallbackIngestBusy
		}
		if err := repo.MarkRunCallbackReceived(ctx, projectID, runID, "engine", current.ResultCount, s.nowFn()); err != nil {
			return err
		}
		result.Processed = true

		callbacks, err := repo.ListDiscoveryCallbacksForRunForUpdate(ctx, projectID, runID)
		if err != nil {
			return err
		}
		finalStatus, finalSummary, ready, err := callbackFinalState(callbacks)
		if err != nil || !ready {
			return err
		}
		before, err := repo.GetTaskRun(ctx, projectID, runID)
		if err != nil {
			return err
		}
		if before.Status != TaskRunStatusRunning {
			return ErrCallbackFinalTransition
		}
		if finalStatus == TaskRunStatusSuccess || finalStatus == TaskRunStatusPartial {
			if err := repo.ApplyDiscoveryObservationLifecycle(ctx, projectID, runID, capabilityForTaskType(before.TaskType),
				s.assetMissThreshold, finalStatus == TaskRunStatusSuccess, "engine", s.nowFn()); err != nil {
				return err
			}
		}
		in := UpdateTaskRunStatusInput{
			ProjectID: projectID, RunID: runID, ActorID: "engine",
			ResultCount: before.ResultCount, ErrorSummary: finalSummary,
		}
		if err := changeTaskRunStatusWith(ctx, repo, before, in, finalStatus, s.nowFn()); err != nil {
			return err
		}
		after, err := repo.GetTaskRun(ctx, projectID, runID)
		if err != nil {
			return err
		}
		if err := s.recordAuditWithSink(ctx, txAudit, ActionRunStatusChange, before, after, "engine", AuditMeta{}); err != nil {
			return err
		}
		result.Finalized = true
		return nil
	})
	return result, err
}

func callbackFinalState(callbacks []*DiscoveryCallback) (status, summary string, ready bool, err error) {
	if len(callbacks) == 0 {
		return "", "", false, nil
	}
	var previous uint64
	for i, callback := range callbacks {
		if callback == nil || callback.IngestStatus != CallbackIngestProcessed {
			return "", "", false, nil
		}
		if (i == 0 && callback.Seq != 1) || (i > 0 && callback.Seq != previous+1) {
			return "", "", false, nil
		}
		previous = callback.Seq
		if i < len(callbacks)-1 && isFinalCallbackPhase(callback.Phase) {
			return "", "", false, ErrCallbackFinalSequence
		}
	}
	final := callbacks[len(callbacks)-1]
	if !isFinalCallbackPhase(final.Phase) {
		return "", "", false, nil
	}
	summary = strings.TrimSpace(final.ErrorSummary)
	switch {
	case final.Phase == CallbackPhaseCompleted && final.Status == TaskRunStatusSuccess:
		return TaskRunStatusSuccess, summary, true, nil
	case final.Phase == CallbackPhaseCompleted && final.Status == TaskRunStatusPartial:
		return TaskRunStatusPartial, summary, true, nil
	case final.Phase == CallbackPhaseCompleted && final.Status == TaskRunStatusCancelled:
		return TaskRunStatusCancelled, summary, true, nil
	case final.Phase == CallbackPhaseFailed && final.Status == TaskRunStatusFailed:
		return TaskRunStatusFailed, summary, true, nil
	default:
		return "", "", false, ErrCallbackFinalTransition
	}
}

func isFinalCallbackPhase(phase string) bool {
	return phase == CallbackPhaseCompleted || phase == CallbackPhaseFailed
}
