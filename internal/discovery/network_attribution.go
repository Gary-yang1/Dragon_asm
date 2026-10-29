package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Network attribution roles, as stored in asset_network_attribution.
const (
	// AttributionCDNEdge marks an address that is a CDN edge, not an origin.
	AttributionCDNEdge = "cdn_edge"
	// AttributionCDNServed marks a name served through a CDN.
	AttributionCDNServed = "cdn_served"
)

// Attribute keys written by the Baiyan DNS stage (engines/baiyan capability
// attribution.go). The engine records evidence; ASM decides what it means.
const (
	factAttrCDNStatus   = "cdn_status"
	factAttrCDNProvider = "cdn_provider"
	factAttrCDNEvidence = "cdn_evidence"
	factAttrRuleVersion = "attribution_rule_version"
	factAttrIPRole      = "ip_role"
)

// attributionRole returns the role a fact's attributes establish for its asset,
// or "" when the engine did not identify an edge. An address needs an explicit
// edge role; a name only needs an identified CDN judgement.
func attributionRole(assetType string, attributes map[string]string) string {
	if attributes[factAttrCDNStatus] != "identified" || strings.TrimSpace(attributes[factAttrRuleVersion]) == "" {
		return ""
	}
	switch assetType {
	case asset.TypeIP:
		if attributes[factAttrIPRole] == AttributionCDNEdge {
			return AttributionCDNEdge
		}
	case asset.TypeDomain, asset.TypeSubdomain:
		return AttributionCDNServed
	}
	return ""
}

func truncateRunes(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8RuneStart(value[limit]) {
		limit--
	}
	return value[:limit]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// upsertNetworkAttribution stores an identified judgement for a materialized
// asset. It never clears one: a later run that cannot tell leaves the last
// identification in place.
func upsertNetworkAttribution(ctx context.Context, tx dbgen.DBTX, callback DiscoveryCallback, item *asset.Asset, attributes map[string]string, observedAt time.Time) error {
	role := attributionRole(item.AssetType, attributes)
	if role == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO asset_network_attribution
 (tenant_id,org_id,project_id,asset_id,role,provider,evidence,rule_version,source_run_id,observed_at)
 VALUES (?,?,?,?,?,?,?,?,?,?)
 ON DUPLICATE KEY UPDATE
  role=IF(VALUES(observed_at)>=observed_at,VALUES(role),role),
  provider=IF(VALUES(observed_at)>=observed_at,VALUES(provider),provider),
  evidence=IF(VALUES(observed_at)>=observed_at,VALUES(evidence),evidence),
  rule_version=IF(VALUES(observed_at)>=observed_at,VALUES(rule_version),rule_version),
  source_run_id=IF(VALUES(observed_at)>=observed_at,VALUES(source_run_id),source_run_id),
  observed_at=GREATEST(observed_at,VALUES(observed_at))`,
		callback.TenantID, callback.OrgID, callback.ProjectID, item.ID, role,
		truncateRunes(attributes[factAttrCDNProvider], 128),
		truncateRunes(attributes[factAttrCDNEvidence], 1024),
		truncateRunes(attributes[factAttrRuleVersion], 64),
		callback.RunID, observedAt.UTC())
	return err
}

// IPNetworkAttribution is what the platform knows about one IP asset's place on
// the network, keyed by its value.
type IPNetworkAttribution struct {
	Value      string
	Role       string
	Provider   string
	ResolvedBy int64
}

// sharedIPMinNames mirrors asset.SharedIPMinNames: addresses at least this many
// live names resolve to are flagged as likely shared, not excluded.
const sharedIPMinNames = 5

// ErrActiveTargetCDNEdge refuses an active task aimed at a CDN edge address.
var ErrActiveTargetCDNEdge = errors.New("discovery: active scanning of a CDN edge address is not allowed")

func ipNetworkByValue(ctx context.Context, repo Repository, projectID uint64, values []string) (map[string]IPNetworkAttribution, error) {
	out := map[string]IPNetworkAttribution{}
	if len(values) == 0 {
		return out, nil
	}
	rows, err := repo.ListIPNetworkAttribution(ctx, projectID, values)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.Value] = row
	}
	return out, nil
}

func cdnLabel(provider string) string {
	if provider == "" {
		return "CDN 边缘节点"
	}
	return provider + " CDN 边缘节点"
}

// applyIPNetwork refines derived IP targets with network attribution. A CDN
// edge is excluded whatever the parent scope says: it is not the organisation's
// address, so confirming it would authorise scanning a third party. A shared
// address stays selectable but says why it needs a closer look.
func applyIPNetwork(ctx context.Context, repo Repository, projectID uint64, items []DerivedTarget) error {
	var values []string
	for _, item := range items {
		if item.TargetType == TargetTypeIP {
			values = append(values, item.Value)
		}
	}
	info, err := ipNetworkByValue(ctx, repo, projectID, values)
	if err != nil {
		return err
	}
	for i := range items {
		network, ok := info[items[i].Value]
		if items[i].TargetType != TargetTypeIP || !ok {
			continue
		}
		switch {
		case network.Role == AttributionCDNEdge:
			items[i].Status = "excluded"
			items[i].Reason = cdnLabel(network.Provider) + "，不是本单位资产，不能作为扫描目标"
		case network.ResolvedBy >= sharedIPMinNames && items[i].Status == "pending":
			items[i].Reason += fmt.Sprintf("；疑似共享地址：被 %d 个域名解析，确认前请核实是否为本单位地址", network.ResolvedBy)
		}
	}
	return nil
}

// refuseCDNEdgeTargets rejects active dispatch to a CDN edge address. It is
// independent of the ownership policy, so turning that policy off cannot route
// a scan at a third party's edge.
func (s *Service) refuseCDNEdgeTargets(ctx context.Context, projectID uint64, taskType string, targets []DispatchTarget) error {
	if !IsActiveTaskType(taskType) {
		return nil
	}
	var values []string
	for _, target := range targets {
		if target.Type == TargetTypeIP {
			values = append(values, strings.TrimSpace(target.Value))
		}
	}
	info, err := ipNetworkByValue(ctx, s.repo, projectID, values)
	if err != nil {
		return err
	}
	for _, value := range values {
		if info[value].Role == AttributionCDNEdge {
			return fmt.Errorf("%w: %s", ErrActiveTargetCDNEdge, value)
		}
	}
	return nil
}
