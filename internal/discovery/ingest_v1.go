//revive:disable:exported

package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	"github.com/Gary-yang1/Dragon_asm/internal/exposure"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var (
	ErrCallbackIngestDB       = errors.New("discovery: callback ingest database is not configured")
	ErrCallbackFactReference  = errors.New("discovery: callback fact reference is unresolved")
	ErrCallbackFactNaturalKey = errors.New("discovery: callback fact natural key is invalid")
)

// IngestCallbackFacts persists provider observations before materializing the
// v1 facts. Every write uses one sql.Tx, including asset/exposure/relation
// upserts and change events; any error rolls the entire batch back.
func (s *Service) IngestCallbackFacts(ctx context.Context, callback DiscoveryCallback) error {
	if s.db == nil {
		return ErrCallbackIngestDB
	}
	payload, err := parseCallbackPayload(callback.Payload)
	if err != nil {
		return err
	}
	if callback.ProjectID == 0 || callback.RunID == 0 || callback.Seq == 0 ||
		payload.RunID != callback.RunID || payload.Seq != callback.Seq {
		return ErrInvalidCallbackPayload
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := s.ingestCallbackFactsWith(ctx, dbgen.New(tx), callback, payload); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Service) ingestCallbackFactsWith(ctx context.Context, q *dbgen.Queries, callback DiscoveryCallback, payload callbackPayload) error {
	discoveryRepo := NewRepository(q)
	run, err := discoveryRepo.GetTaskRun(ctx, callback.ProjectID, callback.RunID)
	if err != nil {
		return err
	}
	if run.TenantID != callback.TenantID || run.OrgID != callback.OrgID {
		return ErrInvalidCallbackPayload
	}
	capability := capabilityForTaskType(run.TaskType)
	assetRepo := asset.NewRepository(q)
	relationRepo := asset.NewRelationRepository(q)
	assetSvc := asset.NewService(assetRepo, asset.WithRelationRepository(relationRepo))
	exposureRepo := exposure.NewRepository(q)
	exposureSvc := exposure.NewService(exposureRepo)
	references := make(map[string]*asset.Asset, len(payload.Assets)*2)

	for _, fact := range payload.Assets {
		normalized, err := asset.Normalize(fact.AssetType, fact.Value)
		if err != nil {
			return err
		}
		observation, err := discoveryRepo.UpsertDiscoveryObservation(ctx, observationFromAssetFact(callback, capability, normalized.Key, fact))
		if err != nil {
			return err
		}
		before, getErr := assetRepo.GetByKey(ctx, callback.ProjectID, normalized.Key)
		if getErr != nil && !errors.Is(getErr, asset.ErrNotFound) {
			return getErr
		}
		materialized, err := assetSvc.Import(ctx, asset.ImportInput{
			TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
			AssetType: fact.AssetType, Value: fact.Value, DisplayName: fact.DisplayName,
			Source: "discovery", Confidence: derefConfidence(fact.Confidence), Status: asset.StatusActive,
			ActorID: "engine", ObservedAt: fact.ObservedAt,
		})
		if err != nil {
			return err
		}
		if assetMateriallyChanged(before, materialized) {
			if err := insertAssetChangeEvent(ctx, exposureRepo, callback, fact, before, materialized); err != nil {
				return err
			}
		}
		if err := discoveryRepo.MarkDiscoveryObservationMaterialized(ctx, callback.ProjectID, observation.ID); err != nil {
			return err
		}
		if err := addFactReferences(references, fact.ClientRef, fact.NaturalKey, normalized.Key, materialized); err != nil {
			return err
		}
	}

	for _, fact := range payload.Relations {
		from, ok := resolveFactReference(ctx, references, assetRepo, callback.ProjectID, fact.From)
		if !ok {
			return ErrCallbackFactReference
		}
		to, ok := resolveFactReference(ctx, references, assetRepo, callback.ProjectID, fact.To)
		if !ok {
			return ErrCallbackFactReference
		}
		naturalKey := callbackFactNaturalKey(fact.NaturalKey, "relation", fact.RelationType, from.AssetKey, to.AssetKey)
		observation, err := discoveryRepo.UpsertDiscoveryObservation(ctx, observationFromRelationFact(callback, capability, naturalKey, fact))
		if err != nil {
			return err
		}
		relationType, err := materializedRelationType(fact.RelationType)
		if err != nil {
			return err
		}
		before, getErr := relationRepo.GetByEndpoints(ctx, callback.ProjectID, from.ID, to.ID, relationType)
		if getErr != nil && !errors.Is(getErr, asset.ErrNotFound) {
			return getErr
		}
		materialized, err := assetSvc.UpsertRelation(ctx, asset.RelationInput{
			TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
			FromAssetID: from.ID, ToAssetID: to.ID, RelationType: relationType,
			Source: "discovery", Confidence: derefConfidence(fact.Confidence), ActorID: "engine", ObservedAt: fact.ObservedAt,
		}, asset.AuditMeta{})
		if err != nil {
			return err
		}
		if before == nil {
			if err := insertRelationChangeEvent(ctx, exposureRepo, callback, fact, materialized); err != nil {
				return err
			}
		}
		if err := discoveryRepo.MarkDiscoveryObservationMaterialized(ctx, callback.ProjectID, observation.ID); err != nil {
			return err
		}
	}

	for _, fact := range payload.Exposures {
		parent, ok := resolveFactReference(ctx, references, assetRepo, callback.ProjectID, fact.Parent)
		if !ok {
			return ErrCallbackFactReference
		}
		naturalKey := callbackFactNaturalKey(fact.NaturalKey, "exposure", fact.ExposureType, parent.AssetKey, fact.Value)
		observation, err := discoveryRepo.UpsertDiscoveryObservation(ctx, observationFromExposureFact(callback, capability, naturalKey, fact))
		if err != nil {
			return err
		}
		if _, err := exposureSvc.Ingest(ctx, exposure.IngestInput{
			TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID, AssetID: parent.ID,
			ExposureType: fact.ExposureType, Value: fact.Value, Name: fact.Value,
			Protocol: fact.Protocol, Port: fact.Port, Service: fact.Service, Version: fact.Version,
			URL: fact.URL, Fingerprint: fact.Fingerprint, EvidenceHash: fact.EvidenceHash,
			Source: "discovery", Confidence: derefConfidence(fact.Confidence), ActorID: "engine", DetectedAt: fact.ObservedAt,
		}); err != nil {
			return err
		}
		if err := discoveryRepo.MarkDiscoveryObservationMaterialized(ctx, callback.ProjectID, observation.ID); err != nil {
			return err
		}
	}

	for _, providerErr := range payload.ProviderErrors {
		naturalKey := callbackFactNaturalKey("", "provider_error", providerErr.Provider, providerErr.Code, fmt.Sprint(callback.Seq))
		raw, err := json.Marshal(providerErr)
		if err != nil {
			return err
		}
		observation, err := discoveryRepo.UpsertDiscoveryObservation(ctx, DiscoveryObservation{
			TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
			RunID: callback.RunID, Seq: callback.Seq, Kind: ObservationKindProviderError,
			NaturalKey: naturalKey, Provider: providerErr.Provider, Capability: capability,
			ObservedAt: payload.ObservedAt, EvidenceHash: callback.PayloadHash,
			NormalizedJSON: raw, IngestStatus: ObservationStatusObserved,
		})
		if err != nil {
			return err
		}
		if err := discoveryRepo.MarkDiscoveryObservationMaterialized(ctx, callback.ProjectID, observation.ID); err != nil {
			return err
		}
	}
	return nil
}

func capabilityForTaskType(taskType string) string {
	switch taskType {
	case TaskTypeDNS:
		return "dns_enrich"
	case TaskTypePassiveIntel:
		return "subdomain_passive"
	default:
		return strings.ToLower(strings.TrimSpace(taskType))
	}
}

func observationFromAssetFact(callback DiscoveryCallback, capability, naturalKey string, fact callbackAssetV1) DiscoveryObservation {
	raw, _ := json.Marshal(fact)
	return baseFactObservation(callback, capability, ObservationKindAsset, naturalKey, fact.callbackFactMeta, raw)
}

func observationFromRelationFact(callback DiscoveryCallback, capability, naturalKey string, fact callbackRelation) DiscoveryObservation {
	raw, _ := json.Marshal(fact)
	return baseFactObservation(callback, capability, ObservationKindRelation, naturalKey, fact.callbackFactMeta, raw)
}

func observationFromExposureFact(callback DiscoveryCallback, capability, naturalKey string, fact callbackExposureV1) DiscoveryObservation {
	raw, _ := json.Marshal(fact)
	return baseFactObservation(callback, capability, ObservationKindExposure, naturalKey, fact.callbackFactMeta, raw)
}

func baseFactObservation(callback DiscoveryCallback, capability, kind, naturalKey string, meta callbackFactMeta, raw []byte) DiscoveryObservation {
	return DiscoveryObservation{
		TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
		RunID: callback.RunID, Seq: callback.Seq, Kind: kind, NaturalKey: naturalKey,
		ClientRef: meta.ClientRef, Provider: meta.Provider, Capability: capability,
		ObservedAt: meta.ObservedAt, Confidence: derefConfidence(meta.Confidence), ActiveProbe: derefBool(meta.ActiveProbe),
		EvidenceHash: meta.EvidenceHash, EvidenceRef: meta.EvidenceRef,
		NormalizedJSON: raw, IngestStatus: ObservationStatusObserved,
	}
}

func addFactReferences(refs map[string]*asset.Asset, clientRef, suppliedNaturalKey, canonicalKey string, item *asset.Asset) error {
	keys := []string{"natural:" + strings.ToLower(strings.TrimSpace(canonicalKey))}
	if clientRef != "" {
		keys = append(keys, "client:"+strings.TrimSpace(clientRef))
	}
	if suppliedNaturalKey != "" {
		keys = append(keys, "natural:"+strings.ToLower(strings.TrimSpace(suppliedNaturalKey)))
	}
	for _, key := range keys {
		if existing, ok := refs[key]; ok && existing.ID != item.ID {
			return ErrCallbackFactNaturalKey
		}
		refs[key] = item
	}
	return nil
}

func resolveFactReference(ctx context.Context, refs map[string]*asset.Asset, repo asset.Repository, projectID uint64, ref callbackFactReference) (*asset.Asset, bool) {
	if ref.ClientRef != "" {
		item, ok := refs["client:"+strings.TrimSpace(ref.ClientRef)]
		if ok {
			return item, true
		}
	}
	naturalKey := strings.ToLower(strings.TrimSpace(ref.NaturalKey))
	item, ok := refs["natural:"+naturalKey]
	if ok {
		return item, true
	}
	if naturalKey == "" {
		return nil, false
	}
	item, err := repo.GetByKey(ctx, projectID, naturalKey)
	return item, err == nil
}

func callbackFactNaturalKey(provided, prefix string, parts ...string) string {
	if normalized := strings.ToLower(strings.TrimSpace(provided)); normalized != "" {
		return normalized
	}
	joined := strings.ToLower(strings.Join(parts, "|"))
	key := prefix + ":" + joined
	if len(key) <= 512 {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return prefix + ":sha256:" + hex.EncodeToString(sum[:])
}

func materializedRelationType(value string) (string, error) {
	switch value {
	case "contains":
		return asset.RelationContains, nil
	case "resolves_to":
		return asset.RelationResolvesTo, nil
	case "cname_to":
		return asset.RelationReferences, nil
	case "presents_certificate":
		return asset.RelationCertBinding, nil
	default:
		return "", asset.ErrInvalidRelationType
	}
}

func derefConfidence(value *uint8) uint8 {
	if value == nil {
		return 0
	}
	return *value
}

func derefBool(value *bool) bool {
	return value != nil && *value
}

func assetMateriallyChanged(before, after *asset.Asset) bool {
	return before == nil || before.AssetType != after.AssetType || before.AssetKey != after.AssetKey ||
		before.DisplayName != after.DisplayName || before.Value != after.Value || before.Source != after.Source ||
		before.Confidence != after.Confidence || before.Status != after.Status
}

func insertAssetChangeEvent(ctx context.Context, repo exposure.Repository, callback DiscoveryCallback, fact callbackAssetV1, before, after *asset.Asset) error {
	changeType := exposure.ChangeTypeModified
	if before == nil {
		changeType = exposure.ChangeTypeNew
	}
	beforeJSON, _ := json.Marshal(assetEventSnapshot(before))
	afterJSON, _ := json.Marshal(assetEventSnapshot(after))
	return repo.InsertChangeEvent(ctx, exposure.ChangeEventParams{
		TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
		EntityType: "asset", EntityID: after.ID, ChangeType: changeType, Severity: exposure.SeverityInfo,
		Title: "Discovery asset " + changeType, Summary: after.AssetType + ":" + after.Value,
		Source: "discovery", Before: beforeJSON, After: afterJSON, DetectedAt: fact.ObservedAt,
	})
}

func insertRelationChangeEvent(ctx context.Context, repo exposure.Repository, callback DiscoveryCallback, fact callbackRelation, relation *asset.Relation) error {
	after, _ := json.Marshal(map[string]any{
		"from_asset_id": relation.FromAssetID, "to_asset_id": relation.ToAssetID,
		"relation_type": fact.RelationType, "source": "discovery",
	})
	return repo.InsertChangeEvent(ctx, exposure.ChangeEventParams{
		TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
		EntityType: "asset", EntityID: relation.FromAssetID, ChangeType: exposure.ChangeTypeModified,
		Severity: exposure.SeverityInfo, Title: "Discovery asset relation", Summary: fact.RelationType,
		Source: "discovery", Before: json.RawMessage(`{}`), After: after, DetectedAt: fact.ObservedAt,
	})
}

func assetEventSnapshot(item *asset.Asset) any {
	if item == nil {
		return nil
	}
	return map[string]any{
		"id": item.ID, "asset_type": item.AssetType, "asset_key": item.AssetKey,
		"value": item.Value, "source": item.Source, "confidence": item.Confidence, "status": item.Status,
	}
}
