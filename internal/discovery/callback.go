//revive:disable:exported

package discovery

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

var (
	ErrInvalidCallbackSignature = errors.New("discovery: invalid callback signature")
	ErrCallbackReplay           = errors.New("discovery: callback replay rejected")
	ErrInvalidCallbackPayload   = errors.New("discovery: invalid callback payload")
	ErrCallbackRunNotRunning    = errors.New("discovery: callback run not running")
	ErrCallbackEnqueue          = errors.New("discovery: callback enqueue failed")
)

const callbackMaxSkew = 5 * time.Minute

// CallbackEnqueuer receives newly accepted callback batches for worker ingest.
type CallbackEnqueuer interface {
	EnqueueDiscoveryCallback(ctx context.Context, cb DiscoveryCallback, rawBody []byte) error
}

type callbackPayload struct {
	RunID        uint64 `json:"run_id"`
	Seq          uint64 `json:"seq"`
	Phase        string `json:"phase"`
	Status       string `json:"status"`
	ResultCount  uint64 `json:"result_count"`
	ErrorSummary string `json:"error_summary"`
}

func (s *Service) HandleCallback(ctx context.Context, in HandleCallbackInput) (HandleCallbackResult, error) {
	if in.ProjectID == 0 || in.RunID == 0 || in.Seq == 0 || len(in.RawBody) == 0 {
		return HandleCallbackResult{}, s.recordCallbackReject(ctx, in, ErrInvalidCallbackPayload, nil)
	}
	if err := verifyCallbackSignature(in.Secret, in.Timestamp, in.Signature, in.RawBody, s.nowFn()); err != nil {
		return HandleCallbackResult{}, s.recordCallbackReject(ctx, in, err, nil)
	}

	payload, err := parseCallbackPayload(in.RawBody)
	if err != nil {
		return HandleCallbackResult{}, s.recordCallbackReject(ctx, in, err, nil)
	}
	if payload.RunID != in.RunID || payload.Seq != in.Seq {
		return HandleCallbackResult{}, s.recordCallbackReject(ctx, in, ErrInvalidCallbackPayload, map[string]any{
			"payload_run_id": payload.RunID,
			"payload_seq":    payload.Seq,
		})
	}

	run, err := s.repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
	if err != nil {
		return HandleCallbackResult{}, s.recordCallbackReject(ctx, in, err, nil)
	}
	if run.Status != TaskRunStatusRunning {
		return HandleCallbackResult{}, s.recordCallbackReject(ctx, in, ErrCallbackRunNotRunning, map[string]any{
			"run_status": run.Status,
		})
	}

	now := s.nowFn()
	cb := DiscoveryCallback{
		TenantID:     run.TenantID,
		OrgID:        run.OrgID,
		ProjectID:    in.ProjectID,
		RunID:        in.RunID,
		Seq:          in.Seq,
		Phase:        payload.Phase,
		Status:       payload.Status,
		PayloadHash:  callbackPayloadHash(in.RawBody),
		ResultCount:  payload.ResultCount,
		ErrorSummary: strings.TrimSpace(payload.ErrorSummary),
		ReceivedAt:   now,
	}

	inserted, err := s.repo.InsertDiscoveryCallback(ctx, cb)
	if err != nil {
		return HandleCallbackResult{}, err
	}
	if !inserted {
		return HandleCallbackResult{Duplicate: true}, nil
	}
	if err := s.repo.MarkRunCallbackReceived(ctx, in.ProjectID, in.RunID, "engine", payload.ResultCount, now); err != nil {
		return HandleCallbackResult{}, err
	}
	if s.callbackEnqueuer != nil {
		if err := s.callbackEnqueuer.EnqueueDiscoveryCallback(ctx, cb, in.RawBody); err != nil {
			return HandleCallbackResult{}, errors.Join(ErrCallbackEnqueue, err)
		}
		if err := s.repo.MarkDiscoveryCallbackEnqueued(ctx, in.ProjectID, in.RunID, in.Seq, s.nowFn()); err != nil {
			return HandleCallbackResult{}, err
		}
	}
	return HandleCallbackResult{}, nil
}

func (s *Service) recordCallbackReject(ctx context.Context, in HandleCallbackInput, reason error, extra map[string]any) error {
	if s.auditSink == nil {
		return reason
	}
	metadata := map[string]any{
		"run_id": in.RunID,
		"seq":    in.Seq,
		"reason": reason.Error(),
	}
	for k, v := range extra {
		metadata[k] = v
	}
	err := s.auditSink.Record(ctx, audit.Event{
		ProjectID:    in.ProjectID,
		ActorID:      "discovery-engine",
		ActorType:    audit.ActorService,
		Action:       ActionCallbackReject,
		ResourceType: ResourceTypeCallback,
		ResourceID:   strconv.FormatUint(in.RunID, 10) + ":" + strconv.FormatUint(in.Seq, 10),
		Result:       audit.ResultFailure,
		Metadata:     metadata,
		ErrorCode:    callbackAuditErrorCode(reason),
		ErrorMessage: reason.Error(),
	})
	if err != nil {
		return errors.Join(reason, err)
	}
	return reason
}

func callbackAuditErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrInvalidCallbackSignature):
		return "INVALID_CALLBACK_SIGNATURE"
	case errors.Is(err, ErrCallbackReplay):
		return "CALLBACK_REPLAY"
	case errors.Is(err, ErrInvalidCallbackPayload):
		return "INVALID_CALLBACK_PAYLOAD"
	case errors.Is(err, ErrCallbackRunNotRunning):
		return "CALLBACK_RUN_NOT_RUNNING"
	case errors.Is(err, ErrNotFound):
		return "DISCOVERY_RUN_NOT_FOUND"
	default:
		return "DISCOVERY_CALLBACK_REJECTED"
	}
}

func verifyCallbackSignature(secret, timestamp, signature string, rawBody []byte, now time.Time) error {
	if strings.TrimSpace(secret) == "" || strings.TrimSpace(timestamp) == "" || strings.TrimSpace(signature) == "" {
		return ErrInvalidCallbackSignature
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return ErrInvalidCallbackSignature
	}
	ts := time.Unix(sec, 0).UTC()
	if now.Sub(ts) > callbackMaxSkew || ts.Sub(now) > callbackMaxSkew {
		return ErrCallbackReplay
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write(rawBody)
	want := mac.Sum(nil)
	gotHex := strings.TrimSpace(signature)
	gotHex = strings.TrimPrefix(gotHex, "sha256=")
	got, err := hex.DecodeString(gotHex)
	if err != nil {
		return ErrInvalidCallbackSignature
	}
	if !hmac.Equal(got, want) {
		return ErrInvalidCallbackSignature
	}
	return nil
}

func parseCallbackPayload(raw []byte) (callbackPayload, error) {
	var payload callbackPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return callbackPayload{}, ErrInvalidCallbackPayload
	}
	if payload.RunID == 0 || payload.Seq == 0 {
		return callbackPayload{}, ErrInvalidCallbackPayload
	}
	switch payload.Phase {
	case CallbackPhaseStarted, CallbackPhaseProgress, CallbackPhaseCompleted, CallbackPhaseFailed:
	default:
		return callbackPayload{}, ErrInvalidCallbackPayload
	}
	if payload.Status != "" && !validTaskStatuses[payload.Status] {
		return callbackPayload{}, ErrInvalidCallbackPayload
	}
	return payload, nil
}

func callbackPayloadHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
