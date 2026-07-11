//revive:disable:exported

package risk

import (
	"encoding/json"
	"time"
)

const (
	TypeVulnerability      = "vulnerability"
	TypeWeakConfig         = "weak_config"
	TypeSensitiveExposure  = "sensitive_exposure"
	TypeUnknownAsset       = "unknown_asset"
	TypeExpiredCertificate = "expired_certificate"
	TypeHighRiskPort       = "high_risk_port"
	TypeHighRiskExposure   = "high_risk_exposure"
	TypeShadowIT           = "shadow_it"
	TypeVendorExposure     = "vendor_exposure"
)

const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

const (
	StatusNew           = "new"
	StatusConfirmed     = "confirmed"
	StatusAssigned      = "assigned"
	StatusFixing        = "fixing"
	StatusRiskAccepted  = "risk_accepted"
	StatusFalsePositive = "false_positive"
	StatusFixed         = "fixed"
	StatusReopened      = "reopened"
)

const (
	EntityTypeRisk     = "risk"
	ChangeTypeNew      = "new"
	ChangeTypeReopened = "reopened"
)

const (
	ActionRiskStatusChange = "risk.status_change"
	ResourceTypeRisk       = "risk"
)

const (
	StatusActionConfirm       = "confirm"
	StatusActionAssign        = "assign"
	StatusActionStartFix      = "start_fix"
	StatusActionMarkFixed     = "mark_fixed"
	StatusActionReopen        = "reopen"
	StatusActionAccept        = "accept"
	StatusActionFalsePositive = "false_positive"
)

type VulnerabilityDefinition struct {
	ID          uint64
	TenantID    string
	OrgID       string
	ProjectID   uint64
	RuleID      string
	CVEID       string
	Title       string
	Description string
	Severity    string
	CPEPattern  string
	Remediation string
	Source      string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   string
	UpdatedBy   string
}

const (
	RuleMatchPort        = "port"
	RuleMatchService     = "service"
	RuleMatchWeb         = "web"
	RuleMatchFingerprint = "fingerprint"
)

type RiskRule struct {
	ID          uint64
	TenantID    string
	OrgID       string
	ProjectID   uint64
	RuleID      string
	Name        string
	Description string
	RiskType    string
	Severity    string
	MatchType   string
	MatchValue  string
	Remediation string
	Source      string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   string
	UpdatedBy   string
}

type Risk struct {
	ID                uint64
	TenantID          string
	OrgID             string
	ProjectID         uint64
	AssetID           uint64
	ExposureID        uint64
	VulnDefinitionID  uint64
	RiskKey           string
	RiskType          string
	Title             string
	Severity          string
	Score             uint8
	ScoreLevel        string
	ScoreModelVersion string
	ScoreFactors      json.RawMessage
	ScoredAt          time.Time
	RuleID            string
	Source            string
	EvidenceSummary   string
	EvidenceRef       string
	Status            string
	Owner             string
	BusinessUnit      string
	SLADueAt          time.Time
	Suppressed        bool
	SuppressionRuleID uint64
	SuppressedUntil   time.Time
	FirstSeen         time.Time
	LastSeen          time.Time
	ConfirmedAt       time.Time
	FixedAt           time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	CreatedBy         string
	UpdatedBy         string
}

type SuppressionRule struct {
	ID        uint64
	TenantID  string
	OrgID     string
	ProjectID uint64
	Name      string
	RiskType  string
	RuleID    string
	AssetID   uint64
	Reason    string
	ExpiresAt time.Time
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
	CreatedBy string
	UpdatedBy string
}

type RiskDecision struct {
	ID               uint64
	TenantID         string
	OrgID            string
	ProjectID        uint64
	RiskID           uint64
	Decision         string
	Reason           string
	ApprovedBy       string
	ExpiresAt        time.Time
	ReviewRequiredAt time.Time
	CreatedAt        time.Time
	CreatedBy        string
}

type SLAPolicy struct {
	ID              uint64
	TenantID        string
	OrgID           string
	ProjectID       uint64
	Severity        string
	BusinessUnit    string
	ResponseHours   uint32
	ResolutionHours uint32
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	CreatedBy       string
	UpdatedBy       string
}

type RiskStatusHistory struct {
	ID        uint64
	TenantID  string
	OrgID     string
	ProjectID uint64
	RiskID    uint64
	Action    string
	OldStatus string
	NewStatus string
	ActorID   string
	Reason    string
	RequestID string
	CreatedAt time.Time
}

type CreateDefinitionInput struct {
	TenantID    string
	OrgID       string
	ProjectID   uint64
	RuleID      string
	CVEID       string
	Title       string
	Description string
	Severity    string
	CPEPattern  string
	Remediation string
	Source      string
	Enabled     bool
	ActorID     string
}

type CreateRuleInput struct {
	TenantID    string
	OrgID       string
	ProjectID   uint64
	RuleID      string
	Name        string
	Description string
	RiskType    string
	Severity    string
	MatchType   string
	MatchValue  string
	Remediation string
	Source      string
	Enabled     bool
	ActorID     string
}

type MatchInput struct {
	TenantID        string
	OrgID           string
	ProjectID       uint64
	AssetID         uint64
	ExposureID      uint64
	CPE             string
	EvidenceSummary string
	EvidenceRef     string
	Owner           string
	BusinessUnit    string
	Source          string
	ObservedAt      time.Time
}

type RuleTarget struct {
	TenantID        string
	OrgID           string
	ProjectID       uint64
	AssetID         uint64
	ExposureID      uint64
	ExposureType    string
	Name            string
	Value           string
	Protocol        string
	Port            uint32
	Service         string
	Version         string
	URL             string
	Fingerprint     string
	CPE             string
	EvidenceSummary string
	EvidenceRef     string
	Owner           string
	BusinessUnit    string
	Source          string
	ObservedAt      time.Time
}

type AuditMeta struct {
	IP        string
	UserAgent string
	RequestID string
}

type StatusTransitionInput struct {
	ProjectID        uint64
	RiskID           uint64
	Action           string
	ActorID          string
	Reason           string
	ApprovedBy       string
	ExpiresAt        time.Time
	ReviewRequiredAt time.Time
	Owner            string
	SLADueAt         time.Time
	Meta             AuditMeta
}

type CreateSuppressionRuleInput struct {
	TenantID  string
	OrgID     string
	ProjectID uint64
	Name      string
	RiskType  string
	RuleID    string
	AssetID   uint64
	Reason    string
	ExpiresAt time.Time
	Enabled   bool
	ActorID   string
}

type UpsertSLAPolicyInput struct {
	TenantID        string
	OrgID           string
	ProjectID       uint64
	Severity        string
	BusinessUnit    string
	ResponseHours   uint32
	ResolutionHours uint32
	Enabled         bool
	ActorID         string
}

type ApplyDefinitionResult struct {
	Risks    []*Risk
	Created  int
	Updated  int
	Reopened int
}

type ApplyRulesResult = ApplyDefinitionResult

type ScoreHistory struct {
	ID                uint64
	TenantID          string
	OrgID             string
	ProjectID         uint64
	RiskID            uint64
	Score             uint8
	ScoreLevel        string
	ScoreModelVersion string
	ScoreFactors      json.RawMessage
	Reason            string
	ScoredAt          time.Time
	CreatedAt         time.Time
	CreatedBy         string
}

type ScoreResult struct {
	Score             uint8
	ScoreLevel        string
	ScoreModelVersion string
	ScoreFactors      json.RawMessage
	ScoredAt          time.Time
}
