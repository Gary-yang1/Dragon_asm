// Package asset implements the asset domain model: the shared, project-scoped
// base that import, discovery, exposure, risk and ticketing all build on.
//
// Every asset lives inside exactly one project. Normalization produces a stable,
// type-prefixed asset_key so repeated discovery of the same real-world asset is
// idempotent (see Normalize + Repository.Upsert).
package asset

import "time"

// Asset type values. These mirror the chk_asset_type CHECK constraint and the
// design-doc taxonomy.
const (
	TypeDomain        = "domain"
	TypeSubdomain     = "subdomain"
	TypeIP            = "ip"
	TypePort          = "port"
	TypeService       = "service"
	TypeWeb           = "web"
	TypeCertificate   = "certificate"
	TypeCloudResource = "cloud_resource"
	TypeThirdParty    = "third_party"
)

// Asset status values. These mirror the chk_asset_status CHECK constraint.
const (
	StatusActive   = "active"
	StatusInactive = "inactive"
	StatusIgnored  = "ignored"
	StatusDeleted  = "deleted"
)

// MaxConfidence is the upper bound enforced by chk_asset_confidence.
const MaxConfidence = 100

// Asset is the storage-agnostic domain representation of an asset. The service
// and its tests use Go-native types only (no DB driver types).
type Asset struct {
	ID           uint64
	TenantID     string
	OrgID        string
	ProjectID    uint64
	AssetType    string
	AssetKey     string
	DisplayName  string
	Value        string
	Source       string
	Owner        string
	BusinessUnit string
	Confidence   uint8
	MissCount    uint32
	Status       string
	FirstSeen    time.Time
	LastSeen     time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	CreatedBy    string
	UpdatedBy    string
}

// validAssetTypes / validStatuses back the enum guards in Normalize/Upsert.
var validAssetTypes = map[string]bool{
	TypeDomain: true, TypeSubdomain: true, TypeIP: true, TypePort: true,
	TypeService: true, TypeWeb: true, TypeCertificate: true,
	TypeCloudResource: true, TypeThirdParty: true,
}

var validStatuses = map[string]bool{
	StatusActive: true, StatusInactive: true, StatusIgnored: true, StatusDeleted: true,
}

// Business-facing asset categories group the storage-level asset types into the
// views operators use most often. They do not change asset identity or storage.
const (
	CategoryDomains  = "domains"
	CategoryIPs      = "ips"
	CategoryWeb      = "web"
	CategoryExternal = "external"
	// CategoryCDNEdges lists addresses identified as CDN edges. They are kept out
	// of CategoryIPs, which is the organisation's own address inventory.
	CategoryCDNEdges = "cdn_edges"
)

// SharedIPMinNames is how many live names must resolve to an address before it
// is labelled as likely shared. It is a hint for review, not an exclusion.
const SharedIPMinNames = 5

var validAssetCategories = map[string]bool{
	CategoryDomains:  true,
	CategoryIPs:      true,
	CategoryWeb:      true,
	CategoryExternal: true,
	CategoryCDNEdges: true,
}

// IsValidType reports whether t is a known asset_type.
func IsValidType(t string) bool { return validAssetTypes[t] }

// IsValidStatus reports whether s is a known asset status.
func IsValidStatus(s string) bool { return validStatuses[s] }

// IsValidCategory reports whether c is a supported business-facing asset view.
func IsValidCategory(c string) bool { return validAssetCategories[c] }

// ListFilter narrows an asset listing. An empty string means "no filter", which
// is how the SQL is written, so the same query serves every combination.
type ListFilter struct {
	ProjectID uint64
	AssetType string
	Category  string
	Status    string
	Keyword   string
	Limit     int32
	Offset    int32
}

// AssetSummary is the project-wide inventory snapshot shown above the asset
// list. Counts are calculated over the complete project result set, never over
// the current page. "New" uses first_seen while "observed" uses last_seen.
type AssetSummary struct {
	Inventory  AssetInventorySummary  `json:"inventory"`
	ByType     AssetTypeSummary       `json:"by_type"`
	Freshness  AssetFreshnessSummary  `json:"freshness"`
	Governance AssetGovernanceSummary `json:"governance"`
	Network    AssetNetworkSummary    `json:"network"`
}

// AssetNetworkSummary counts addresses that are not the organisation's own:
// identified CDN edges (excluded from every other figure) and addresses shared
// by many names (still counted, only labelled).
type AssetNetworkSummary struct {
	CDNEdge          int64 `json:"cdn_edge"`
	SharedIP         int64 `json:"shared_ip"`
	SharedIPMinNames int   `json:"shared_ip_min_names"`
}

type AssetInventorySummary struct {
	Total        int64 `json:"total"`
	ManagedTotal int64 `json:"managed_total"`
	Active       int64 `json:"active"`
	Inactive     int64 `json:"inactive"`
	Ignored      int64 `json:"ignored"`
}

type AssetTypeSummary struct {
	Domain        int64 `json:"domain"`
	Subdomain     int64 `json:"subdomain"`
	IP            int64 `json:"ip"`
	Port          int64 `json:"port"`
	Service       int64 `json:"service"`
	Web           int64 `json:"web"`
	Certificate   int64 `json:"certificate"`
	CloudResource int64 `json:"cloud_resource"`
	ThirdParty    int64 `json:"third_party"`
}

type AssetFreshnessSummary struct {
	New24H      int64 `json:"new_24h"`
	Observed24H int64 `json:"observed_24h"`
	Stale30D    int64 `json:"stale_30d"`
}

type AssetGovernanceSummary struct {
	Unowned                int64 `json:"unowned"`
	UnassignedBusinessUnit int64 `json:"unassigned_business_unit"`
	LowConfidence          int64 `json:"low_confidence"`
	LowConfidenceBelow     uint8 `json:"low_confidence_below"`
}

// AssetGraph is the bounded, one-hop topology around a focus asset. Nodes carry
// display data so the UI never needs to fall back to an opaque database ID.
type AssetGraph struct {
	Nodes     []AssetGraphNode `json:"nodes"`
	Edges     []AssetGraphEdge `json:"edges"`
	Truncated bool             `json:"truncated"`
}

type AssetGraphNode struct {
	ID           uint64    `json:"id"`
	AssetType    string    `json:"asset_type"`
	DisplayName  string    `json:"display_name"`
	Value        string    `json:"value"`
	Status       string    `json:"status"`
	Source       string    `json:"source"`
	Owner        string    `json:"owner"`
	BusinessUnit string    `json:"business_unit"`
	Confidence   uint8     `json:"confidence"`
	LastSeen     time.Time `json:"last_seen"`
	Focus        bool      `json:"focus"`
}

type AssetGraphEdge struct {
	ID           uint64    `json:"id"`
	FromAssetID  uint64    `json:"from_asset_id"`
	ToAssetID    uint64    `json:"to_asset_id"`
	RelationType string    `json:"relation_type"`
	Source       string    `json:"source"`
	Confidence   uint8     `json:"confidence"`
	LastSeen     time.Time `json:"last_seen"`
}
