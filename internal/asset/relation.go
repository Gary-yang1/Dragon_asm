// Package asset's relation model: directed edges between two assets within one
// project. Relations are the base layer for the later discovery pipeline and the
// exposure graph; this file defines the domain shape, the relation_type enum and
// the direction tags returned by the list API.

package asset

import "time"

// Relation type values. These mirror the chk_relation_type CHECK constraint.
const (
	RelationContains    = "contains"     // parent contains child (domain→subdomain, ip→port)
	RelationResolvesTo  = "resolves_to"  // DNS resolution (domain/subdomain→ip)
	RelationRedirectsTo = "redirects_to" // HTTP redirect (web→web)
	RelationCertBinding = "cert_binding" // certificate bound to a domain (certificate→domain)
	RelationReferences  = "references"   // generic reference
)

// Direction tags reported by the list API for a relation relative to the queried
// asset. "out" means the queried asset is the source (from_asset_id); "in" means
// it is the target (to_asset_id).
const (
	DirectionOut = "out"
	DirectionIn  = "in"
)

// MaxRelationConfidence mirrors chk_relation_confidence.
const MaxRelationConfidence = 100

// Relation is the storage-agnostic domain representation of an asset edge. The
// service fills Direction relative to the queried asset before returning it; it
// is not a stored column.
type Relation struct {
	ID           uint64
	TenantID     string
	OrgID        string
	ProjectID    uint64
	FromAssetID  uint64
	ToAssetID    uint64
	RelationType string
	Source       string
	Confidence   uint8
	Direction    string // "out" | "in" — relative to the queried asset; empty for non-list contexts
	FirstSeen    time.Time
	LastSeen     time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	CreatedBy    string
	UpdatedBy    string
}

var validRelationTypes = map[string]bool{
	RelationContains: true, RelationResolvesTo: true, RelationRedirectsTo: true,
	RelationCertBinding: true, RelationReferences: true,
}

// IsValidRelationType reports whether t is a known relation_type.
func IsValidRelationType(t string) bool { return validRelationTypes[t] }

// IsValidDirection reports whether d is a supported list direction.
func IsValidDirection(d string) bool {
	switch d {
	case DirectionOut, DirectionIn:
		return true
	default:
		return false
	}
}
