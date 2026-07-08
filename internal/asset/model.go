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

// IsValidType reports whether t is a known asset_type.
func IsValidType(t string) bool { return validAssetTypes[t] }

// IsValidStatus reports whether s is a known asset status.
func IsValidStatus(s string) bool { return validStatuses[s] }
