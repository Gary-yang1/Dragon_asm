package project

import "time"

// Project workspace status, profile classification, and verification values.
const (
	StatusDraft = "draft"

	CriticalityLow      = "low"
	CriticalityMedium   = "medium"
	CriticalityHigh     = "high"
	CriticalityCritical = "critical"

	VerificationUnverified = "unverified"
	VerificationVerified   = "verified"
	VerificationMismatch   = "mismatch"

	FilingStatusValid     = "valid"
	FilingStatusInvalid   = "invalid"
	FilingStatusCancelled = "cancelled"
)

// AuditMeta carries request metadata persisted with a workspace mutation.
type AuditMeta struct {
	IP        string
	UserAgent string
	RequestID string
}

// ActorScope identifies the tenant and organization resolved for an actor.
type ActorScope struct {
	TenantID string
	OrgID    string
}

// List is a paginated set of projects visible to the actor.
type List struct {
	Items []*Project
	Total int64
}

// WorkspaceSummary is the tenant-safe aggregate shown on the global workspace.
// RecentProjects contains at most five projects ordered by last update.
type WorkspaceSummary struct {
	Projects       WorkspaceProjectStats `json:"projects"`
	Assets         WorkspaceAssetStats   `json:"assets"`
	Risks          WorkspaceRiskStats    `json:"risks"`
	Tickets        WorkspaceTicketStats  `json:"tickets"`
	RecentProjects []WorkspaceProject    `json:"recent_projects"`
}

// WorkspaceProjectStats contains project lifecycle totals visible to the actor.
type WorkspaceProjectStats struct {
	Total     int64 `json:"total"`
	Active    int64 `json:"active"`
	Draft     int64 `json:"draft"`
	Suspended int64 `json:"suspended"`
}

// WorkspaceAssetStats contains visible live asset totals.
type WorkspaceAssetStats struct {
	Total int64 `json:"total"`
}

// WorkspaceRiskStats contains non-terminal risk totals.
type WorkspaceRiskStats struct {
	Open         int64 `json:"open"`
	CriticalHigh int64 `json:"critical_high"`
	Overdue      int64 `json:"overdue"`
}

// WorkspaceTicketStats contains non-terminal remediation ticket totals.
type WorkspaceTicketStats struct {
	Open    int64 `json:"open"`
	Overdue int64 `json:"overdue"`
}

// WorkspaceProject is the compact recent-project representation.
type WorkspaceProject struct {
	ID           uint64    `json:"id"`
	ProjectCode  string    `json:"project_code"`
	Name         string    `json:"name"`
	OwnerUserID  string    `json:"owner_user_id"`
	BusinessUnit string    `json:"business_unit"`
	Criticality  string    `json:"criticality"`
	Status       string    `json:"status"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Capabilities describes the actor's effective abilities in one project.
type Capabilities struct {
	Role              string   `json:"role"`
	Permissions       []string `json:"permissions"`
	CanActivate       bool     `json:"can_activate"`
	OnboardingMissing []string `json:"onboarding_missing"`
}

// CreateProjectInput contains validated-at-service project creation fields.
type CreateProjectInput struct {
	ProjectCode  string
	Name         string
	OwnerUserID  string
	BusinessUnit string
	Criticality  string
	Description  string
	ActorID      string
	Meta         AuditMeta
}

// UpdateProjectInput describes a partial project update.
type UpdateProjectInput struct {
	ProjectID    uint64
	Name         *string
	OwnerUserID  *string
	BusinessUnit *string
	Criticality  *string
	Description  *string
	ActorID      string
	Meta         AuditMeta
}

// TransitionProjectInput requests an audited project status transition.
type TransitionProjectInput struct {
	ProjectID uint64
	Status    string
	Reason    string
	ActorID   string
	Meta      AuditMeta
}

// Subject represents an organization or person associated with a project.
type Subject struct {
	ID                 uint64     `json:"id"`
	ProjectID          uint64     `json:"project_id"`
	SubjectName        string     `json:"subject_name"`
	SubjectType        string     `json:"subject_type"`
	RegistrationCode   string     `json:"registration_code"`
	CountryCode        string     `json:"country_code"`
	Region             string     `json:"region"`
	IsPrimary          bool       `json:"is_primary"`
	VerificationStatus string     `json:"verification_status"`
	Source             string     `json:"source"`
	VerifiedAt         *time.Time `json:"verified_at,omitempty"`
	EvidenceSummary    string     `json:"evidence_summary"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// SubjectInput contains fields shared by subject create and update operations.
type SubjectInput struct {
	ProjectID          uint64
	SubjectID          uint64
	SubjectName        string
	SubjectType        string
	RegistrationCode   string
	CountryCode        string
	Region             string
	IsPrimary          bool
	VerificationStatus string
	Source             string
	VerifiedAt         *time.Time
	EvidenceSummary    string
	ActorID            string
	Meta               AuditMeta
}

// DomainProfile links a registrable root domain asset to project metadata.
type DomainProfile struct {
	ID              uint64    `json:"id"`
	ProjectID       uint64    `json:"project_id"`
	AssetID         uint64    `json:"asset_id"`
	Domain          string    `json:"domain"`
	SubjectID       uint64    `json:"subject_id,omitempty"`
	IsPrimary       bool      `json:"is_primary"`
	OwnershipStatus string    `json:"ownership_status"`
	Source          string    `json:"source"`
	EvidenceSummary string    `json:"evidence_summary"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// DomainInput contains fields shared by domain profile create and update operations.
type DomainInput struct {
	ProjectID       uint64
	DomainProfileID uint64
	Domain          string
	SubjectID       uint64
	IsPrimary       bool
	OwnershipStatus string
	Source          string
	EvidenceSummary string
	ActorID         string
	Meta            AuditMeta
}

// ICPFilings represents an ICP filing and its linked project domains.
type ICPFilings struct {
	ID               uint64     `json:"id"`
	ProjectID        uint64     `json:"project_id"`
	SubjectID        uint64     `json:"subject_id"`
	FilingNo         string     `json:"filing_no"`
	FilingType       string     `json:"filing_type"`
	WebsiteName      string     `json:"website_name"`
	Status           string     `json:"status"`
	ApprovedAt       *time.Time `json:"approved_at,omitempty"`
	Source           string     `json:"source"`
	VerifiedAt       *time.Time `json:"verified_at,omitempty"`
	EvidenceSummary  string     `json:"evidence_summary"`
	DomainProfileIDs []uint64   `json:"domain_profile_ids"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// ICPInput contains fields shared by ICP filing create and update operations.
type ICPInput struct {
	ProjectID        uint64
	FilingID         uint64
	SubjectID        uint64
	FilingNo         string
	FilingType       string
	WebsiteName      string
	Status           string
	ApprovedAt       *time.Time
	Source           string
	VerifiedAt       *time.Time
	EvidenceSummary  string
	DomainProfileIDs []uint64
	ActorID          string
	Meta             AuditMeta
}

// OnboardingStatus reports whether a draft project satisfies activation gates.
type OnboardingStatus struct {
	OwnerConfigured          bool     `json:"owner_configured"`
	PrimarySubjectConfigured bool     `json:"primary_subject_configured"`
	PrimaryDomainConfigured  bool     `json:"primary_domain_configured"`
	ValidScopeConfigured     bool     `json:"valid_scope_configured"`
	ReadyToActivate          bool     `json:"ready_to_activate"`
	Missing                  []string `json:"missing"`
}

// CreateProjectParams is the repository contract for inserting a project.
type CreateProjectParams struct {
	ActorScope
	ProjectCode  string
	Name         string
	Owner        string
	BusinessUnit string
	Criticality  string
	Description  string
	ActorID      string
}

// UpdateProjectParams is the repository contract for updating a project.
type UpdateProjectParams struct {
	ID           uint64
	Name         string
	Owner        string
	BusinessUnit string
	Criticality  string
	Description  string
	ActorID      string
}
