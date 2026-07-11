//revive:disable:exported

package discovery

import "time"

const (
	StatusActive   = "active"
	StatusInactive = "inactive"
)

const (
	TaskTypeDNS          = "dns"
	TaskTypeCTLog        = "ct_log"
	TaskTypePortProbe    = "port_probe"
	TaskTypeWebProbe     = "web_probe"
	TaskTypeFingerprint  = "fingerprint"
	TaskTypeCloudSync    = "cloud_sync"
	TaskTypePassiveIntel = "passive_intel"
	TaskTypeImport       = "import"
)

const (
	TaskRunStatusPending   = "pending"
	TaskRunStatusRunning   = "running"
	TaskRunStatusSuccess   = "success"
	TaskRunStatusPartial   = "partial_success"
	TaskRunStatusFailed    = "failed"
	TaskRunStatusCancelled = "cancelled"
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

// Action names and resource type for scope/template/run audit events.
const (
	ActionScopeCreate        = "scope.create"
	ActionScopeUpdate        = "scope.update"
	ActionScopeDeactivate    = "scope.deactivate"
	ActionTemplateCreate     = "discovery.template.create"
	ActionTemplateUpdate     = "discovery.template.update"
	ActionTemplateDelete     = "discovery.template.delete"
	ActionTemplateEnable     = "discovery.template.enable"
	ActionRunCreate          = "discovery.run.create"
	ActionRunStatusChange    = "discovery.run.status_change"
	ActionRunCancel          = "discovery.run.cancel"
	ActionCallbackReject     = "discovery.callback.reject"
	ResourceTypeScope        = "scope"
	ResourceTypeTaskTemplate = "task_template"
	ResourceTypeTaskRun      = "task_run"
	ResourceTypeCallback     = "discovery_callback"
)

// DispatchTarget is a normalized target that has passed local format checks.
type DispatchTarget struct {
	Type  string
	Value string
}

// DispatchPlan is the safe, pre-authorized plan consumed by the future engine adapter.
type DispatchPlan struct {
	RunID          uint64
	TemplateID     uint64
	ProjectID      uint64
	ScopeID        uint64
	TaskType       string
	Targets        []DispatchTarget
	RateLimit      int
	Concurrency    int
	TimeoutSeconds int
	RetryLimit     int
	Options        map[string]any
}

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

// TaskTemplate defines how one discovery strategy should be executed.
type TaskTemplate struct {
	ID             uint64
	TenantID       string
	OrgID          string
	ProjectID      uint64
	ScopeID        uint64
	Name           string
	TaskType       string
	Config         string
	Schedule       string
	Enabled        bool
	TimeoutSeconds int
	RateLimit      int
	Concurrency    int
	RetryLimit     int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CreatedBy      string
	UpdatedBy      string
	DeletedAt      time.Time
	Targets        []*ScopeTarget
}

// TaskRun records one execution instance for an operator trigger or scheduler.
type TaskRun struct {
	ID                uint64
	TenantID          string
	OrgID             string
	ProjectID         uint64
	TemplateID        uint64
	ScopeID           uint64
	TaskType          string
	Status            string
	Progress          int
	TimeoutSeconds    int
	RateLimit         int
	Concurrency       int
	RetryLimit        int
	Attempt           int
	EngineJobID       string
	DispatchedAt      time.Time
	LastCallbackAt    time.Time
	ResultCount       uint64
	CallbackSecretRef string
	StartedAt         time.Time
	FinishedAt        time.Time
	ErrorSummary      string
	CreatedBy         string
	UpdatedBy         string
	DeletedAt         time.Time
}

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

// TaskTemplateTargetInput intentionally reuses scope-style target literals for
// request decoding consistency.
type TaskTemplateTargetInput = ScopeTargetInput

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

// CreateTaskTemplateInput is the service input for a task template.
type CreateTaskTemplateInput struct {
	TenantID       string
	OrgID          string
	ProjectID      uint64
	ScopeID        uint64
	Name           string
	TaskType       string
	Config         string
	Schedule       string
	Enabled        bool
	TimeoutSeconds int
	RateLimit      int
	Concurrency    int
	RetryLimit     int
	ActorID        string
	Meta           AuditMeta
}

// UpdateTaskTemplateInput patches one task template.
type UpdateTaskTemplateInput struct {
	TemplateID     uint64
	TenantID       string
	OrgID          string
	ProjectID      uint64
	Name           *string
	TaskType       *string
	Config         *string
	Schedule       *string
	TimeoutSeconds *int
	RateLimit      *int
	Concurrency    *int
	RetryLimit     *int
	ActorID        string
	Meta           AuditMeta
}

// SetTaskTemplateEnabledInput toggles template scheduling availability.
type SetTaskTemplateEnabledInput struct {
	TemplateID uint64
	ProjectID  uint64
	Enabled    bool
	ActorID    string
	Meta       AuditMeta
}

// DeleteTaskTemplateInput soft-deletes one template.
type DeleteTaskTemplateInput struct {
	TemplateID uint64
	ProjectID  uint64
	ActorID    string
	Meta       AuditMeta
}

// CreateTaskRunInput creates one on-demand run for an existing template.
type CreateTaskRunInput struct {
	TemplateID uint64
	ProjectID  uint64
	ActorID    string
	Meta       AuditMeta
}

// UpdateTaskRunStatusInput updates status and terminal fields for one run.
type UpdateTaskRunStatusInput struct {
	RunID        uint64
	ProjectID    uint64
	Status       string
	ErrorSummary string
	ResultCount  uint64
	ActorID      string
	Meta         AuditMeta
}

// IncrementTaskRunAttemptInput increments one run attempt.
type IncrementTaskRunAttemptInput struct {
	RunID     uint64
	ProjectID uint64
	ActorID   string
	Meta      AuditMeta
}

// Engine callback phases accepted by the callback receiver.
const (
	CallbackPhaseStarted   = "started"
	CallbackPhaseProgress  = "progress"
	CallbackPhaseCompleted = "completed"
	CallbackPhaseFailed    = "failed"
)

// DiscoveryCallback records one idempotent callback batch from the engine.
type DiscoveryCallback struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	RunID        uint64
	Seq          uint64
	Phase        string
	Status       string
	PayloadHash  string
	ResultCount  uint64
	ErrorSummary string
	ReceivedAt   time.Time
}

// HandleCallbackInput is the verified callback processing input.
type HandleCallbackInput struct {
	ProjectID uint64
	RunID     uint64
	Seq       uint64
	Timestamp string
	Signature string
	RawBody   []byte
	Secret    string
}

// HandleCallbackResult reports whether the callback was new or already seen.
type HandleCallbackResult struct {
	Duplicate bool
}

// AuditMeta carries request-scope metadata for audit payloads.
type AuditMeta struct {
	IP        string
	UserAgent string
	RequestID string
}
