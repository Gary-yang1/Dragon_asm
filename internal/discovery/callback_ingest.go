//revive:disable:exported

package discovery

import (
	"context"
	"encoding/json"
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
		// The receipt bookkeeping (last_callback_at, result_count) is scoped to
		// running rows, so it must be skipped once the run has closed — otherwise
		// draining a leftover out-of-contract callback fails the whole transaction
		// and the worker retries that row until its attempt budget is gone.
		runBefore, err := repo.GetTaskRun(ctx, projectID, runID)
		if err != nil {
			return err
		}
		if runBefore.Status == TaskRunStatusRunning {
			if err := repo.MarkRunCallbackReceived(ctx, projectID, runID, "engine", current.ResultCount, s.nowFn()); err != nil {
				return err
			}
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
			// A callback arriving after the run already closed. If the run is already
			// in the state this callback implies there is nothing to do, and erroring
			// would roll back the "processed" mark and make the worker retry the same
			// callback until it exhausts its attempt budget.
			if before.Status == finalStatus {
				return nil
			}
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

// callbackFinalState decides whether a run can be finalised from its inbox.
//
// The engine declares the end of a run by sending a final-phase callback. The rule
// is therefore "every callback up to and including that marker has been ingested",
// not "the whole list is dense" — a single callback numbered beyond the marker is a
// protocol violation by the sender and must not hold the run open. Requiring
// density over the entire list meant one injected seq (say 999999) left the run in
// `running` until the reconcile worker eventually timed it out, so a successful
// scan was recorded as a timeout and the asset lifecycle pass never ran.
func callbackFinalState(callbacks []*DiscoveryCallback) (status, summary string, ready bool, err error) {
	if len(callbacks) == 0 {
		return "", "", false, nil
	}

	// The lowest-numbered final-phase callback is the authoritative end of the run.
	// A later one contradicts a completion the engine already declared, so it is
	// treated as out-of-contract like any other extra: the run closes on the first
	// marker and the stray row stays in the inbox as evidence. Erroring instead
	// would roll back the ingest and have the worker retry it until its attempt
	// budget ran out, which is the wedge this function had to begin with.
	var final *DiscoveryCallback
	for _, callback := range callbacks {
		if callback == nil {
			return "", "", false, nil
		}
		if isFinalCallbackPhase(callback.Phase) && (final == nil || callback.Seq < final.Seq) {
			final = callback
		}
	}
	if final == nil {
		return "", "", false, nil
	}

	seen := make(map[uint64]bool, len(callbacks))
	for _, callback := range callbacks {
		if callback.Seq > final.Seq {
			continue
		}
		if callback.IngestStatus != CallbackIngestProcessed {
			return "", "", false, nil
		}
		seen[callback.Seq] = true
	}
	// A real gap below the marker means facts are still missing: keep waiting.
	for want := uint64(1); want <= final.Seq; want++ {
		if !seen[want] {
			return "", "", false, nil
		}
	}
	summary = strings.TrimSpace(final.ErrorSummary)
	if summary == "" {
		var payload callbackPayload
		if json.Unmarshal(final.Payload, &payload) == nil {
			parts := []string{}
			for _, e := range payload.ProviderErrors {
				parts = append(parts, e.Provider+": "+e.Code)
			}
			summary = strings.Join(parts, "; ")
			if len(summary) > 1000 {
				summary = summary[:1000]
			}
		}
	}
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
