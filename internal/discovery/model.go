package discovery

import "time"

const (
	StatusActive   = "active"
	StatusInactive = "inactive"
)

const (
	TargetTypeDomain = "domain"
	TargetTypeIP     = "ip"
	TargetTypeCIDR   = "cidr"
	TargetTypeURL    = "url"
)

const (
	MatchModeInclude = "include"
	MatchModeExclude = "exclude"
)

// Scope contains the authorization window for discovery operations.
type Scope struct {
	ID           uint64
	TenantID     string
	OrgID        string
	ProjectID    uint64
	Name         string
	Status       string
	AuthorizedBy string
	ValidFrom    time.Time
	ValidUntil   time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	CreatedBy    string
	UpdatedBy    string
	DeletedAt    time.Time
	Targets      []*ScopeTarget
}

// ScopeTarget is one include/exclude policy entry for one scope.
type ScopeTarget struct {
	ID         uint64
	TenantID   string
	OrgID      string
	ProjectID  uint64
	ScopeID    uint64
	TargetType string
	MatchMode  string
	Value      string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	CreatedBy  string
	UpdatedBy  string
	DeletedAt  time.Time
}

// Action names and resource type for scope audit events.
const (
	ActionScopeCreate     = "scope.create"
	ActionScopeUpdate     = "scope.update"
	ActionScopeDeactivate = "scope.deactivate"
	ResourceTypeScope     = "scope"
)

// ScopeRejectReason is returned by IsTargetAllowed for deterministic engine reuse.
type ScopeRejectReason string

const (
	ReasonAllowed       ScopeRejectReason = "ALLOWED"
	ReasonScopeNotFound ScopeRejectReason = "SCOPE_NOT_FOUND"
	ReasonScopeInactive ScopeRejectReason = "SCOPE_INACTIVE"
	ReasonNotStarted    ScopeRejectReason = "SCOPE_NOT_STARTED"
	ReasonScopeExpired  ScopeRejectReason = "SCOPE_EXPIRED"
	ReasonTargetInvalid ScopeRejectReason = "INVALID_TARGET"
	ReasonDangerous     ScopeRejectReason = "DANGEROUS_TARGET"
	ReasonExcluded      ScopeRejectReason = "TARGET_EXCLUDED"
	ReasonNoMatch       ScopeRejectReason = "NO_MATCH"
	ReasonSystemError   ScopeRejectReason = "SYSTEM_ERROR"
)

// ScopeTargetInput is input for create/update operations.
type ScopeTargetInput struct {
	TargetType string
	MatchMode  string
	Value      string
}

// CreateScopeInput is the service input for a new scope.
type CreateScopeInput struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	Name         string
	AuthorizedBy string
	ValidFrom    time.Time
	ValidUntil   time.Time
	Status       string
	ActorID      string
	Meta         AuditMeta
	Targets      []ScopeTargetInput
}

// UpdateScopeInput applies partial updates for one scope.
type UpdateScopeInput struct {
	ScopeID      uint64
	TenantID     string
	OrgID        string
	ProjectID    uint64
	Name         *string
	AuthorizedBy *string
	ValidFrom    *time.Time
	ValidUntil   *time.Time
	Status       *string
	ActorID      string
	Meta         AuditMeta
	Targets      *[]ScopeTargetInput
}

// DeactivateScopeInput marks a live scope inactive.
type DeactivateScopeInput struct {
	ScopeID   uint64
	ProjectID uint64
	ActorID   string
	Meta      AuditMeta
}

// AuditMeta carries request-scope metadata for audit payloads.
type AuditMeta struct {
	IP        string
	UserAgent string
	RequestID string
}
