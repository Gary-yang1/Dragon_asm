package discovery

import (
	"context"
	"encoding/json"
	"math"
	"time"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

func (r *sqlcRepository) ApplyDiscoveryObservationLifecycle(
	ctx context.Context,
	projectID, runID uint64,
	capability string,
	missThreshold uint32,
	allowMiss bool,
	actorID string,
	now time.Time,
) error {
	if missThreshold == 0 {
		missThreshold = 3
	}
	keys, err := r.q.ListCurrentDiscoveryAssetObservationKeys(ctx, dbgen.ListCurrentDiscoveryAssetObservationKeysParams{
		ProjectID: projectID, RunID: runID, Capability: capability,
	})
	if err != nil {
		return err
	}
	hits := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		hits[key] = struct{}{}
	}
	assets, err := r.q.ListDiscoveryLifecycleAssets(ctx, dbgen.ListDiscoveryLifecycleAssetsParams{
		ProjectID: projectID, Capability: capability,
	})
	if err != nil {
		return err
	}
	for _, item := range assets {
		newMiss := item.MissCount
		newStatus := item.Status
		_, hit := hits[item.AssetKey]
		switch {
		case hit:
			newMiss = 0
			if item.Status == "inactive" {
				newStatus = "active"
			}
		case !allowMiss || item.Status == "ignored":
			continue
		default:
			if newMiss < math.MaxUint32 {
				newMiss++
			}
			if item.Status == "active" && newMiss >= missThreshold {
				newStatus = "inactive"
			}
		}
		if newMiss == item.MissCount && newStatus == item.Status {
			continue
		}
		if err := r.q.UpdateAssetLifecycle(ctx, dbgen.UpdateAssetLifecycleParams{
			MissCount: newMiss, Status: newStatus, UpdatedBy: actorID, ID: item.ID, ProjectID: projectID,
		}); err != nil {
			return err
		}
		before, _ := json.Marshal(map[string]any{"miss_count": item.MissCount, "status": item.Status})
		after, _ := json.Marshal(map[string]any{"miss_count": newMiss, "status": newStatus})
		if _, err := r.q.InsertChangeEvent(ctx, dbgen.InsertChangeEventParams{
			TenantID: item.TenantID, OrgID: item.OrgID, ProjectID: projectID,
			EntityType: "asset", EntityID: item.ID, ChangeType: "modified", Severity: "info",
			Title: "Discovery asset lifecycle", Summary: capability,
			Source: "discovery", BeforeJson: before, AfterJson: after, DetectedAt: now.UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}
