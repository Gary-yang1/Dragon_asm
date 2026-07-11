package auth

import "time"

// Tenant-level platform role values are separate from project-member roles.
const (
	PlatformRoleNone          = ""
	PlatformRoleSystemAdmin   = "system_admin"
	PlatformRoleSecurityAdmin = "security_admin"
)

// PlatformUser is the administrative account view. It intentionally excludes
// password hashes and auth_version so those values cannot escape through API DTOs.
type PlatformUser struct {
	ID                 uint64
	TenantID           string
	OrgID              string
	Username           string
	DisplayName        string
	Email              string
	Phone              string
	Department         string
	Role               string
	Status             string
	ProjectCount       int64
	LastLoginAt        *time.Time
	MustChangePassword bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// PlatformUserProject is a read-only project membership shown to administrators.
type PlatformUserProject struct {
	ID          uint64
	ProjectCode string
	Name        string
	Role        string
	Status      string
	UpdatedAt   time.Time
}

// PlatformUserListFilter contains validated tenant-list filters and pagination.
type PlatformUserListFilter struct {
	Search string
	Status string
	Role   string
	Limit  int32
	Offset int32
}

// PlatformUserList is a paginated tenant-scoped user result.
type PlatformUserList struct {
	Items []*PlatformUser
	Total int64
}

// CreatePlatformUserInput carries administrator-provided account data.
type CreatePlatformUserInput struct {
	Username    string
	DisplayName string
	Email       string
	Phone       string
	Department  string
	Role        string
	Status      string
	Password    string
	ActorID     string
	Meta        AdminAuditMeta
}

// UpdatePlatformUserInput carries mutable profile fields only.
type UpdatePlatformUserInput struct {
	UserID      uint64
	DisplayName *string
	Email       *string
	Phone       *string
	Department  *string
	ActorID     string
	Meta        AdminAuditMeta
}

// TransitionPlatformUserInput requests an audited enable/disable transition.
type TransitionPlatformUserInput struct {
	UserID  uint64
	Status  string
	Reason  string
	ActorID string
	Meta    AdminAuditMeta
}

// ResetPlatformUserPasswordInput requests an audited temporary-password reset.
type ResetPlatformUserPasswordInput struct {
	UserID            uint64
	TemporaryPassword string
	ActorID           string
	Meta              AdminAuditMeta
}

// UpdateTenantRoleInput sets or clears a tenant-level platform role.
type UpdateTenantRoleInput struct {
	UserID  uint64
	Role    string
	ActorID string
	Meta    AdminAuditMeta
}

// AdminAuditMeta carries request context persisted with security-sensitive changes.
type AdminAuditMeta struct {
	IP        string
	UserAgent string
	RequestID string
}

// AdminRole describes one entry in the fixed read-only role matrix.
type AdminRole struct {
	Value       string
	Label       string
	Scope       string
	Permissions []string
}
