//revive:disable:exported

package discovery

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/hibiken/asynq"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	"github.com/Gary-yang1/Dragon_asm/internal/exposure"
)

// AssetImporter is the asset service subset used by discovery result ingest.
type AssetImporter interface {
	Import(ctx context.Context, in asset.ImportInput) (*asset.Asset, error)
}

// ExposureIngester is the exposure service subset used by discovery result ingest.
type ExposureIngester interface {
	Ingest(ctx context.Context, in exposure.IngestInput) (*exposure.IngestResult, error)
}

// CallbackInboxReader loads the durable callback body by the identifiers kept
// in Redis. This keeps bounded raw payloads out of the queue backend.
type CallbackInboxManager interface {
	GetDiscoveryCallback(ctx context.Context, projectID, runID, seq uint64) (*DiscoveryCallback, error)
	ClaimDiscoveryCallbackIngest(ctx context.Context, projectID, runID, seq uint64) (bool, error)
	FailDiscoveryCallbackIngest(ctx context.Context, projectID, runID, seq uint64) error
	CompleteDiscoveryCallbackIngest(ctx context.Context, projectID, runID, seq uint64) (CompleteCallbackIngestResult, error)
}

type CallbackFactIngester interface {
	IngestCallbackFacts(ctx context.Context, callback DiscoveryCallback) error
}

type callbackIngestPayload struct {
	Callback DiscoveryCallback
	RawBody  json.RawMessage
}

// IngestHandler is the M2-5 worker entrypoint for normalized result ingestion.
type IngestHandler struct {
	assets    AssetImporter
	exposures ExposureIngester
	inbox     CallbackInboxManager
	facts     CallbackFactIngester
	logger    *slog.Logger
}

func NewIngestHandler(importer AssetImporter, logger *slog.Logger) *IngestHandler {
	return &IngestHandler{assets: importer, logger: logger}
}

func (h *IngestHandler) WithExposureIngester(ingester ExposureIngester) *IngestHandler {
	h.exposures = ingester
	return h
}

func (h *IngestHandler) WithCallbackInbox(inbox CallbackInboxManager) *IngestHandler {
	h.inbox = inbox
	return h
}

func (h *IngestHandler) WithCallbackFactIngester(ingester CallbackFactIngester) *IngestHandler {
	h.facts = ingester
	return h
}

func (h *IngestHandler) Register(mux *asynq.ServeMux) {
	mux.HandleFunc(TaskTypeIngestScanResult, h.Handle)
}

func (h *IngestHandler) Handle(ctx context.Context, task *asynq.Task) error {
	var ref CallbackTaskPayload
	if err := json.Unmarshal(task.Payload(), &ref); err != nil {
		return err
	}
	if ref.ProjectID == 0 || ref.RunID == 0 || ref.Seq == 0 || h.inbox == nil {
		return ErrInvalidCallbackPayload
	}
	stored, err := h.inbox.GetDiscoveryCallback(ctx, ref.ProjectID, ref.RunID, ref.Seq)
	if err != nil {
		return err
	}
	if stored.IngestStatus == CallbackIngestProcessed {
		return nil
	}
	claimed, err := h.inbox.ClaimDiscoveryCallbackIngest(ctx, ref.ProjectID, ref.RunID, ref.Seq)
	if err != nil {
		return err
	}
	if !claimed {
		latest, getErr := h.inbox.GetDiscoveryCallback(ctx, ref.ProjectID, ref.RunID, ref.Seq)
		if getErr == nil && latest.IngestStatus == CallbackIngestProcessed {
			return nil
		}
		return ErrCallbackIngestBusy
	}
	payload := callbackIngestPayload{Callback: *stored, RawBody: json.RawMessage(stored.Payload)}
	if err := h.ingest(ctx, payload); err != nil {
		_ = h.inbox.FailDiscoveryCallbackIngest(ctx, ref.ProjectID, ref.RunID, ref.Seq)
		return err
	}
	_, err = h.inbox.CompleteDiscoveryCallbackIngest(ctx, ref.ProjectID, ref.RunID, ref.Seq)
	return err
}

func (h *IngestHandler) ingest(ctx context.Context, payload callbackIngestPayload) error {
	if h.facts != nil {
		return h.facts.IngestCallbackFacts(ctx, payload.Callback)
	}
	if h.assets != nil {
		body, err := parseCallbackResult(payload.RawBody)
		if err != nil {
			return err
		}
		for _, item := range body.Assets {
			if _, err := h.importAsset(ctx, payload, item); err != nil {
				return err
			}
		}
		if h.exposures != nil {
			for _, item := range body.Exposures {
				parent, err := h.importAsset(ctx, payload, item.callbackAsset)
				if err != nil {
					return err
				}
				if item.ExposureType == exposure.TypeCertificate {
					if _, err := h.importCertificateAsset(ctx, payload, item); err != nil {
						return err
					}
				}
				if _, err := h.exposures.Ingest(ctx, exposure.IngestInput{
					TenantID:      payload.Callback.TenantID,
					OrgID:         payload.Callback.OrgID,
					ProjectID:     payload.Callback.ProjectID,
					AssetID:       parent.ID,
					ExposureType:  item.ExposureType,
					ExposureKey:   item.ExposureKey,
					Name:          item.Name,
					Value:         item.ExposureValue,
					Protocol:      item.Protocol,
					Port:          item.Port,
					Service:       item.Service,
					Version:       item.Version,
					CPE:           item.CPE,
					URL:           item.URL,
					Fingerprint:   item.Fingerprint,
					CertSubject:   item.CertSubject,
					CertIssuer:    item.CertIssuer,
					CertSerial:    item.CertSerial,
					CertNotBefore: item.CertNotBefore,
					CertNotAfter:  item.CertNotAfter,
					CertSANs:      item.CertSANs,
					EvidenceHash:  item.EvidenceHash,
					Source:        defaultString(item.Source, "discovery"),
					Confidence:    item.Confidence,
					ActorID:       "engine",
					DetectedAt:    payload.Callback.ReceivedAt,
				}); err != nil {
					return err
				}
			}
		}
	}
	if h.logger != nil {
		body := parseCallbackResultNoErr(payload.RawBody)
		h.logger.Info("discovery callback accepted for ingest",
			"project_id", payload.Callback.ProjectID,
			"run_id", payload.Callback.RunID,
			"seq", payload.Callback.Seq,
			"phase", payload.Callback.Phase,
			"assets", len(body.Assets),
			"exposures", len(body.Exposures),
		)
	}
	return nil
}

func (h *IngestHandler) importAsset(ctx context.Context, payload callbackIngestPayload, item callbackAsset) (*asset.Asset, error) {
	return h.assets.Import(ctx, asset.ImportInput{
		TenantID:     payload.Callback.TenantID,
		OrgID:        payload.Callback.OrgID,
		ProjectID:    payload.Callback.ProjectID,
		AssetType:    item.AssetType,
		Value:        item.Value,
		DisplayName:  item.DisplayName,
		Source:       defaultString(item.Source, "discovery"),
		Owner:        item.Owner,
		BusinessUnit: item.BusinessUnit,
		Confidence:   item.Confidence,
		Status:       asset.StatusActive,
		ActorID:      "engine",
	})
}

func (h *IngestHandler) importCertificateAsset(ctx context.Context, payload callbackIngestPayload, item callbackExposure) (*asset.Asset, error) {
	value := strings.TrimSpace(item.Fingerprint)
	if value == "" {
		value = strings.TrimSpace(item.CertSerial)
	}
	if value == "" {
		value = strings.TrimSpace(item.CertSubject)
	}
	if value == "" {
		return nil, ErrInvalidCallbackPayload
	}
	return h.assets.Import(ctx, asset.ImportInput{
		TenantID:    payload.Callback.TenantID,
		OrgID:       payload.Callback.OrgID,
		ProjectID:   payload.Callback.ProjectID,
		AssetType:   asset.TypeCertificate,
		Value:       value,
		DisplayName: item.CertSubject,
		Source:      defaultString(item.Source, "discovery"),
		Confidence:  item.Confidence,
		Status:      asset.StatusActive,
		ActorID:     "engine",
	})
}

type callbackResultBody struct {
	Assets    []callbackAsset    `json:"assets"`
	Exposures []callbackExposure `json:"exposures"`
}

type callbackAsset struct {
	AssetType    string `json:"asset_type"`
	Value        string `json:"value"`
	DisplayName  string `json:"display_name"`
	Source       string `json:"source"`
	Owner        string `json:"owner"`
	BusinessUnit string `json:"business_unit"`
	Confidence   uint8  `json:"confidence"`
}

type callbackExposure struct {
	callbackAsset
	ExposureType  string    `json:"exposure_type"`
	ExposureKey   string    `json:"exposure_key"`
	Name          string    `json:"name"`
	ExposureValue string    `json:"exposure_value"`
	Protocol      string    `json:"protocol"`
	Port          uint32    `json:"port"`
	Service       string    `json:"service"`
	Version       string    `json:"version"`
	CPE           string    `json:"cpe"`
	URL           string    `json:"url"`
	Fingerprint   string    `json:"fingerprint"`
	CertSubject   string    `json:"cert_subject"`
	CertIssuer    string    `json:"cert_issuer"`
	CertSerial    string    `json:"cert_serial"`
	CertNotBefore time.Time `json:"cert_not_before"`
	CertNotAfter  time.Time `json:"cert_not_after"`
	CertSANs      []string  `json:"cert_sans"`
	EvidenceHash  string    `json:"evidence_hash"`
}

func parseCallbackResult(raw json.RawMessage) (callbackResultBody, error) {
	if len(raw) == 0 {
		return callbackResultBody{}, nil
	}
	var body callbackResultBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return callbackResultBody{}, err
	}
	for _, item := range body.Assets {
		if strings.TrimSpace(item.AssetType) == "" || strings.TrimSpace(item.Value) == "" {
			return callbackResultBody{}, ErrInvalidCallbackPayload
		}
	}
	for _, item := range body.Exposures {
		if strings.TrimSpace(item.AssetType) == "" ||
			strings.TrimSpace(item.Value) == "" ||
			strings.TrimSpace(item.ExposureType) == "" {
			return callbackResultBody{}, ErrInvalidCallbackPayload
		}
	}
	return body, nil
}

func parseCallbackResultNoErr(raw json.RawMessage) callbackResultBody {
	body, err := parseCallbackResult(raw)
	if err != nil {
		return callbackResultBody{}
	}
	return body
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
