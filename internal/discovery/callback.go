//revive:disable:exported

package discovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

var (
	ErrInvalidCallbackSignature  = errors.New("discovery: invalid callback signature")
	ErrInvalidCallbackIdentity   = errors.New("discovery: invalid callback engine identity")
	ErrCallbackReplay            = errors.New("discovery: callback replay rejected")
	ErrInvalidCallbackPayload    = errors.New("discovery: invalid callback payload")
	ErrCallbackSchemaUnsupported = errors.New("discovery: callback schema unsupported")
	ErrCallbackPayloadConflict   = errors.New("discovery: callback payload conflict")
	ErrCallbackTooLarge          = errors.New("discovery: callback payload too large")
	ErrCallbackRunNotRunning     = errors.New("discovery: callback run not running")
	ErrCallbackEnqueue           = errors.New("discovery: callback enqueue failed")
)

const (
	callbackSchemaVersion   = "1.0"
	callbackMaxSkew         = 5 * time.Minute
	callbackMaxBodyBytes    = 4 << 20
	callbackMaxAssets       = 1000
	callbackMaxRelations    = 1000
	callbackMaxExposures    = 1000
	callbackMaxFacts        = 2000
	callbackMaxProviderErrs = 100
	callbackMaxRefLen       = 512
	callbackMaxSourceLen    = 64
	callbackMaxAssetValue   = 2048
	callbackMaxValueLen     = 4096
	callbackMaxErrorLen     = 1024
)

// CallbackEnqueuer receives durable callback identifiers for worker ingest.
// Raw payload bytes remain in MySQL and are never copied into Redis.
type CallbackEnqueuer interface {
	EnqueueDiscoveryCallback(ctx context.Context, cb DiscoveryCallback) error
}

type callbackPayload struct {
	SchemaVersion  string                  `json:"schema_version"`
	RunID          uint64                  `json:"run_id"`
	Seq            uint64                  `json:"seq"`
	Phase          string                  `json:"phase"`
	Status         string                  `json:"status"`
	ResultCount    uint64                  `json:"result_count"`
	ObservedAt     time.Time               `json:"observed_at"`
	Assets         []callbackAssetV1       `json:"assets"`
	Relations      []callbackRelation      `json:"relations"`
	Exposures      []callbackExposureV1    `json:"exposures"`
	ProviderErrors []callbackProviderError `json:"provider_errors"`
	ErrorSummary   string                  `json:"error_summary"`
}

type callbackFactMeta struct {
	ClientRef    string    `json:"client_ref"`
	NaturalKey   string    `json:"natural_key"`
	Source       string    `json:"source"`
	Provider     string    `json:"provider"`
	ObservedAt   time.Time `json:"observed_at"`
	Confidence   *uint8    `json:"confidence"`
	ActiveProbe  *bool     `json:"active_probe"`
	EvidenceHash string    `json:"evidence_hash"`
	EvidenceRef  string    `json:"evidence_ref"`
}

type callbackAssetV1 struct {
	callbackFactMeta
	AssetType   string            `json:"asset_type"`
	Value       string            `json:"value"`
	DisplayName string            `json:"display_name"`
	Attributes  map[string]string `json:"attributes"`
}

type callbackFactReference struct {
	ClientRef  string `json:"client_ref"`
	NaturalKey string `json:"natural_key"`
}

type callbackRelation struct {
	callbackFactMeta
	RelationType string                `json:"relation_type"`
	From         callbackFactReference `json:"from"`
	To           callbackFactReference `json:"to"`
}

type callbackExposureV1 struct {
	callbackFactMeta
	Parent       callbackFactReference `json:"parent"`
	ExposureType string                `json:"exposure_type"`
	Value        string                `json:"value"`
	Protocol     string                `json:"protocol"`
	Port         uint32                `json:"port"`
	Service      string                `json:"service"`
	Version      string                `json:"version"`
	URL          string                `json:"url"`
	Fingerprint  string                `json:"fingerprint"`
}

type callbackProviderError struct {
	Provider  string `json:"provider"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable *bool  `json:"retryable"`
}

// RecoverPendingCallbacks re-enqueues durable inbox rows after Redis or API
// interruption. The periodic worker trigger is wired in EXT-04.
func (s *Service) RecoverPendingCallbacks(ctx context.Context, limit int32) (int, error) {
	if s.callbackEnqueuer == nil {
		return 0, ErrCallbackEnqueue
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	items, err := s.repo.ListPendingDiscoveryCallbacks(ctx, limit)
	if err != nil {
		return 0, err
	}
	recovered := 0
	var recoveryErrors []error
	for _, item := range items {
		if err := s.enqueueStoredCallback(ctx, item); err != nil {
			recoveryErrors = append(recoveryErrors, err)
			continue
		}
		recovered++
	}
	return recovered, errors.Join(recoveryErrors...)
}

func (s *Service) HandleCallback(ctx context.Context, in HandleCallbackInput) (HandleCallbackResult, error) {
	if in.ProjectID == 0 || in.RunID == 0 || in.Seq == 0 || len(in.RawBody) == 0 {
		return HandleCallbackResult{}, s.recordCallbackReject(ctx, in, ErrInvalidCallbackPayload, nil)
	}
	if len(in.RawBody) > callbackMaxBodyBytes {
		return HandleCallbackResult{}, s.recordCallbackReject(ctx, in, ErrCallbackTooLarge, nil)
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

	hash := callbackPayloadHash(in.RawBody)
	// The body is rejected above at 4 MiB, so this conversion cannot overflow.
	payloadSize := uint32(len(in.RawBody)) // #nosec G115
	now := s.nowFn()
	duplicate := false
	var stored *DiscoveryCallback
	err = s.runInTx(ctx, func(ctx context.Context, repo Repository, _ auditRecorder) error {
		run, err := repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
		if err != nil {
			return err
		}
		if run.CallbackSecretRef != "" && !hmac.Equal([]byte(run.CallbackSecretRef), []byte(strings.TrimSpace(in.SecretRef))) {
			return ErrInvalidCallbackSignature
		}

		existing, getErr := repo.GetDiscoveryCallback(ctx, in.ProjectID, in.RunID, in.Seq)
		if getErr == nil {
			if existing.PayloadHash != hash {
				return ErrCallbackPayloadConflict
			}
			duplicate = true
			stored = existing
			return nil
		}
		if !errors.Is(getErr, ErrNotFound) {
			return getErr
		}
		if run.Status != TaskRunStatusRunning {
			return ErrCallbackRunNotRunning
		}

		candidate := DiscoveryCallback{
			TenantID: run.TenantID, OrgID: run.OrgID, ProjectID: in.ProjectID,
			RunID: in.RunID, Seq: in.Seq, SchemaVersion: payload.SchemaVersion,
			Phase: payload.Phase, Status: payload.Status, ObservedAt: payload.ObservedAt,
			PayloadHash: hash, Payload: append([]byte(nil), in.RawBody...), PayloadSize: payloadSize,
			ResultCount: payload.ResultCount, ErrorSummary: strings.TrimSpace(payload.ErrorSummary),
			ReceivedAt: now, IngestStatus: CallbackIngestPending,
		}
		inserted, insertErr := repo.InsertDiscoveryCallback(ctx, candidate)
		if insertErr != nil {
			return insertErr
		}
		if !inserted {
			existing, getErr = repo.GetDiscoveryCallback(ctx, in.ProjectID, in.RunID, in.Seq)
			if getErr != nil {
				return getErr
			}
			if existing.PayloadHash != hash {
				return ErrCallbackPayloadConflict
			}
			duplicate = true
			stored = existing
			return nil
		}
		// Result count is applied only after first successful ingest in EXT-04.
		if err := repo.MarkRunCallbackReceived(ctx, in.ProjectID, in.RunID, "engine", 0, now); err != nil {
			return err
		}
		stored = &candidate
		return nil
	})
	if err != nil {
		return HandleCallbackResult{}, s.recordCallbackReject(ctx, in, err, nil)
	}

	if stored != nil && stored.IngestStatus == CallbackIngestPending {
		if err := s.enqueueStoredCallback(ctx, stored); err != nil {
			return HandleCallbackResult{}, err
		}
	}
	return HandleCallbackResult{Duplicate: duplicate}, nil
}

func validCallbackIdentity(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return false
	}
	for index, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		if index > 0 && (r == '.' || r == '_' || r == '-' || r == ':') {
			continue
		}
		return false
	}
	return true
}

func (s *Service) enqueueStoredCallback(ctx context.Context, cb *DiscoveryCallback) error {
	if s.callbackEnqueuer == nil || cb == nil {
		return ErrCallbackEnqueue
	}
	if err := s.callbackEnqueuer.EnqueueDiscoveryCallback(ctx, *cb); err != nil {
		return errors.Join(ErrCallbackEnqueue, err)
	}
	if err := s.repo.MarkDiscoveryCallbackEnqueued(ctx, cb.ProjectID, cb.RunID, cb.Seq, s.nowFn()); err != nil {
		return errors.Join(ErrCallbackEnqueue, err)
	}
	return nil
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
	case errors.Is(err, ErrCallbackTooLarge):
		return "CALLBACK_TOO_LARGE"
	case errors.Is(err, ErrCallbackSchemaUnsupported):
		return "CALLBACK_SCHEMA_UNSUPPORTED"
	case errors.Is(err, ErrCallbackPayloadConflict):
		return "CALLBACK_PAYLOAD_CONFLICT"
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
	gotHex := strings.TrimPrefix(strings.TrimSpace(signature), "sha256=")
	got, err := hex.DecodeString(gotHex)
	if err != nil || !hmac.Equal(got, want) {
		return ErrInvalidCallbackSignature
	}
	return nil
}

func parseCallbackPayload(raw []byte) (callbackPayload, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || !hasCallbackRequiredFields(fields) {
		return callbackPayload{}, ErrInvalidCallbackPayload
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload callbackPayload
	if err := decoder.Decode(&payload); err != nil {
		return callbackPayload{}, ErrInvalidCallbackPayload
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return callbackPayload{}, ErrInvalidCallbackPayload
	}
	if payload.SchemaVersion != callbackSchemaVersion {
		return callbackPayload{}, ErrCallbackSchemaUnsupported
	}
	if err := validateCallbackPayload(payload); err != nil {
		return callbackPayload{}, err
	}
	return payload, nil
}

func validateCallbackPayload(payload callbackPayload) error {
	if payload.RunID == 0 || payload.Seq == 0 || payload.ObservedAt.IsZero() || len(payload.ErrorSummary) > callbackMaxErrorLen ||
		payload.Assets == nil || payload.Relations == nil || payload.Exposures == nil || payload.ProviderErrors == nil {
		return ErrInvalidCallbackPayload
	}
	switch payload.Phase {
	case CallbackPhaseStarted, CallbackPhaseProgress:
		if payload.Status != TaskRunStatusRunning {
			return ErrInvalidCallbackPayload
		}
	case CallbackPhaseCompleted:
		if payload.Status != TaskRunStatusSuccess && payload.Status != TaskRunStatusPartial && payload.Status != TaskRunStatusCancelled {
			return ErrInvalidCallbackPayload
		}
	case CallbackPhaseFailed:
		if payload.Status != TaskRunStatusFailed {
			return ErrInvalidCallbackPayload
		}
	default:
		return ErrInvalidCallbackPayload
	}
	if len(payload.Assets) > callbackMaxAssets || len(payload.Relations) > callbackMaxRelations ||
		len(payload.Exposures) > callbackMaxExposures || len(payload.ProviderErrors) > callbackMaxProviderErrs {
		return ErrInvalidCallbackPayload
	}
	factCount := len(payload.Assets) + len(payload.Relations) + len(payload.Exposures)
	if factCount > callbackMaxFacts || payload.ResultCount != uint64(factCount) {
		return ErrInvalidCallbackPayload
	}
	for _, item := range payload.Assets {
		if !validCallbackMeta(item.callbackFactMeta) || !validAssetType(item.AssetType) ||
			len(strings.TrimSpace(item.Value)) == 0 || len(item.Value) > callbackMaxAssetValue || len(item.DisplayName) > 255 || len(item.Attributes) > 32 {
			return ErrInvalidCallbackPayload
		}
		for key, value := range item.Attributes {
			if len(key) == 0 || len(key) > 64 || len(value) > 1024 {
				return ErrInvalidCallbackPayload
			}
		}
	}
	for _, item := range payload.Relations {
		if !validCallbackMeta(item.callbackFactMeta) || !validFactReference(item.From) || !validFactReference(item.To) ||
			!validRelationType(item.RelationType) {
			return ErrInvalidCallbackPayload
		}
	}
	for _, item := range payload.Exposures {
		if !validCallbackMeta(item.callbackFactMeta) || !validFactReference(item.Parent) ||
			!validExposureType(item.ExposureType) || len(strings.TrimSpace(item.Value)) == 0 || len(item.Value) > callbackMaxValueLen ||
			len(item.Protocol) > 16 || item.Port > 65535 || len(item.Service) > 128 || len(item.Version) > 128 ||
			len(item.URL) > 2048 || len(item.Fingerprint) > 512 {
			return ErrInvalidCallbackPayload
		}
	}
	for _, providerErr := range payload.ProviderErrors {
		if len(strings.TrimSpace(providerErr.Provider)) == 0 || len(providerErr.Provider) > callbackMaxSourceLen ||
			!validProviderErrorCode(providerErr.Code) || len(providerErr.Message) > 512 || providerErr.Retryable == nil {
			return ErrInvalidCallbackPayload
		}
	}
	return nil
}

func validCallbackMeta(meta callbackFactMeta) bool {
	if (strings.TrimSpace(meta.ClientRef) == "" && strings.TrimSpace(meta.NaturalKey) == "") ||
		len(meta.ClientRef) > 128 || len(meta.NaturalKey) > callbackMaxRefLen ||
		len(strings.TrimSpace(meta.Source)) == 0 || len(meta.Source) > callbackMaxSourceLen ||
		len(strings.TrimSpace(meta.Provider)) == 0 || len(meta.Provider) > callbackMaxSourceLen ||
		meta.ObservedAt.IsZero() || meta.Confidence == nil || *meta.Confidence > 100 ||
		meta.ActiveProbe == nil || *meta.ActiveProbe || len(meta.EvidenceRef) > callbackMaxRefLen {
		return false
	}
	decoded, err := hex.DecodeString(meta.EvidenceHash)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(meta.EvidenceHash) == meta.EvidenceHash
}

func hasCallbackRequiredFields(fields map[string]json.RawMessage) bool {
	for _, key := range []string{
		"schema_version", "run_id", "seq", "phase", "status", "result_count", "observed_at",
		"assets", "relations", "exposures", "provider_errors", "error_summary",
	} {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	return true
}

func validProviderErrorCode(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for i := 1; i < len(value); i++ {
		if (value[i] < 'A' || value[i] > 'Z') && (value[i] < '0' || value[i] > '9') && value[i] != '_' {
			return false
		}
	}
	return true
}

func validFactReference(ref callbackFactReference) bool {
	return (strings.TrimSpace(ref.ClientRef) != "" || strings.TrimSpace(ref.NaturalKey) != "") &&
		len(ref.ClientRef) <= 128 && len(ref.NaturalKey) <= callbackMaxRefLen
}

func validAssetType(value string) bool {
	switch value {
	case "domain", "subdomain", "ip", "certificate":
		return true
	default:
		return false
	}
}

func validRelationType(value string) bool {
	switch value {
	case "contains", "resolves_to", "cname_to", "presents_certificate":
		return true
	default:
		return false
	}
}

func validExposureType(value string) bool {
	switch value {
	case "port", "service", "web", "certificate":
		return true
	default:
		return false
	}
}

func callbackPayloadHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
