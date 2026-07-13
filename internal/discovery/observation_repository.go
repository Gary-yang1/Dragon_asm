//revive:disable:exported

package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var ErrInvalidDiscoveryObservation = errors.New("discovery: invalid observation")

const maxObservationJSONBytes = 64 << 10

func (r *sqlcRepository) UpsertDiscoveryObservation(ctx context.Context, in DiscoveryObservation) (*DiscoveryObservation, error) {
	normalized, err := normalizeDiscoveryObservation(in)
	if err != nil {
		return nil, err
	}
	result, err := r.q.UpsertDiscoveryObservation(ctx, dbgen.UpsertDiscoveryObservationParams{
		TenantID: normalized.TenantID, OrgID: normalized.OrgID, ProjectID: normalized.ProjectID,
		RunID: normalized.RunID, Seq: normalized.Seq, Kind: normalized.Kind, NaturalKey: normalized.NaturalKey,
		ClientRef: normalized.ClientRef, Provider: normalized.Provider, Capability: normalized.Capability,
		ObservedAt: normalized.ObservedAt.UTC(), Confidence: normalized.Confidence, ActiveProbe: normalized.ActiveProbe,
		EvidenceHash: normalized.EvidenceHash, EvidenceRef: normalized.EvidenceRef,
		NormalizedJson: normalized.NormalizedJSON, NormalizedSize: normalized.NormalizedSize,
		IngestStatus: normalized.IngestStatus, IngestError: normalized.IngestError,
	})
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil || id <= 0 {
		return nil, errors.Join(ErrInvalidDiscoveryObservation, err)
	}
	return r.GetDiscoveryObservation(ctx, normalized.ProjectID, uint64(id)) // #nosec G115 -- MySQL AUTO_INCREMENT is unsigned-positive here
}

func (r *sqlcRepository) GetDiscoveryObservation(ctx context.Context, projectID, observationID uint64) (*DiscoveryObservation, error) {
	row, err := r.q.GetDiscoveryObservation(ctx, dbgen.GetDiscoveryObservationParams{ID: observationID, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return observationFromDB(row), nil
}

func (r *sqlcRepository) ListDiscoveryObservationsByRun(ctx context.Context, projectID, runID, seq uint64) ([]*DiscoveryObservation, error) {
	var rows []dbgen.DiscoveryObservation
	var err error
	if seq == 0 {
		rows, err = r.q.ListDiscoveryObservationsByRun(ctx, dbgen.ListDiscoveryObservationsByRunParams{ProjectID: projectID, RunID: runID})
	} else {
		rows, err = r.q.ListDiscoveryObservationsByRunSeq(ctx, dbgen.ListDiscoveryObservationsByRunSeqParams{ProjectID: projectID, RunID: runID, Seq: seq})
	}
	if err != nil {
		return nil, err
	}
	return observationsFromDB(rows), nil
}

func (r *sqlcRepository) ListDiscoveryObservationsByNaturalKey(ctx context.Context, projectID uint64, kind, naturalKey string) ([]*DiscoveryObservation, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	naturalKey = strings.ToLower(strings.TrimSpace(naturalKey))
	if projectID == 0 || !validObservationKind(kind) || !validBoundedText(naturalKey, 512, false) {
		return nil, ErrInvalidDiscoveryObservation
	}
	rows, err := r.q.ListDiscoveryObservationsByNaturalKey(ctx, dbgen.ListDiscoveryObservationsByNaturalKeyParams{
		ProjectID: projectID, Kind: kind, NaturalKey: naturalKey,
	})
	if err != nil {
		return nil, err
	}
	return observationsFromDB(rows), nil
}

func (r *sqlcRepository) MarkDiscoveryObservationMaterialized(ctx context.Context, projectID, observationID uint64) error {
	return r.q.MarkDiscoveryObservationMaterialized(ctx, dbgen.MarkDiscoveryObservationMaterializedParams{
		ID: observationID, ProjectID: projectID,
	})
}

func normalizeDiscoveryObservation(in DiscoveryObservation) (DiscoveryObservation, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.OrgID = strings.TrimSpace(in.OrgID)
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	in.NaturalKey = strings.ToLower(strings.TrimSpace(in.NaturalKey))
	in.ClientRef = strings.TrimSpace(in.ClientRef)
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	in.Capability = strings.ToLower(strings.TrimSpace(in.Capability))
	in.EvidenceHash = strings.ToLower(strings.TrimSpace(in.EvidenceHash))
	in.EvidenceRef = strings.TrimSpace(in.EvidenceRef)
	in.IngestStatus = strings.ToLower(strings.TrimSpace(in.IngestStatus))
	in.IngestError = strings.TrimSpace(in.IngestError)
	if in.IngestStatus == "" {
		in.IngestStatus = ObservationStatusObserved
	}
	if in.ProjectID == 0 || in.RunID == 0 || in.Seq == 0 ||
		!validBoundedText(in.TenantID, 64, false) || !validBoundedText(in.OrgID, 64, false) ||
		!validObservationKind(in.Kind) || !validBoundedText(in.NaturalKey, 512, false) ||
		!validBoundedText(in.ClientRef, 128, true) || !validObservationIdentifier(in.Provider) ||
		!validObservationIdentifier(in.Capability) || in.ObservedAt.IsZero() || in.Confidence > 100 ||
		!validEvidenceHash(in.EvidenceHash) || !validBoundedText(in.EvidenceRef, 512, true) ||
		!validObservationStatus(in.IngestStatus) || !validBoundedText(in.IngestError, 1024, true) {
		return DiscoveryObservation{}, ErrInvalidDiscoveryObservation
	}
	if len(in.NormalizedJSON) == 0 || len(in.NormalizedJSON) > maxObservationJSONBytes || !safeNormalizedObservationJSON(in.NormalizedJSON) {
		return DiscoveryObservation{}, ErrInvalidDiscoveryObservation
	}
	in.NormalizedSize = uint32(len(in.NormalizedJSON)) // #nosec G115 -- bounded to 64 KiB above
	in.NormalizedJSON = append([]byte(nil), in.NormalizedJSON...)
	return in, nil
}

func validObservationKind(kind string) bool {
	switch kind {
	case ObservationKindAsset, ObservationKindRelation, ObservationKindExposure, ObservationKindProviderError:
		return true
	default:
		return false
	}
}

func validObservationStatus(status string) bool {
	return status == ObservationStatusObserved || status == ObservationStatusMaterialized || status == ObservationStatusFailed
}

func validObservationIdentifier(value string) bool {
	if !validBoundedText(value, 64, false) {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func validBoundedText(value string, max int, emptyOK bool) bool {
	return utf8.ValidString(value) && len(value) <= max && (emptyOK || value != "") && !strings.ContainsRune(value, '\x00')
}

func validEvidenceHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func safeNormalizedObservationJSON(raw []byte) bool {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return false
	}
	return !containsSensitiveObservationKey(value)
}

func containsSensitiveObservationKey(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
			switch normalized {
			case "token", "access_token", "refresh_token", "cookie", "set_cookie", "authorization", "password", "secret", "api_key":
				return true
			}
			if containsSensitiveObservationKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSensitiveObservationKey(child) {
				return true
			}
		}
	}
	return false
}

func observationFromDB(row dbgen.DiscoveryObservation) *DiscoveryObservation {
	return &DiscoveryObservation{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		RunID: row.RunID, Seq: row.Seq, Kind: row.Kind, NaturalKey: row.NaturalKey,
		ClientRef: row.ClientRef, Provider: row.Provider, Capability: row.Capability,
		ObservedAt: row.ObservedAt, Confidence: row.Confidence, ActiveProbe: row.ActiveProbe,
		EvidenceHash: row.EvidenceHash, EvidenceRef: row.EvidenceRef,
		NormalizedJSON: append([]byte(nil), row.NormalizedJson...), NormalizedSize: row.NormalizedSize,
		IngestStatus: row.IngestStatus, IngestError: row.IngestError,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, DeletedAt: row.DeletedAt,
	}
}

func observationsFromDB(rows []dbgen.DiscoveryObservation) []*DiscoveryObservation {
	items := make([]*DiscoveryObservation, 0, len(rows))
	for _, row := range rows {
		items = append(items, observationFromDB(row))
	}
	return items
}
