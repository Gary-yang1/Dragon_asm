package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Platform-user audit action and resource names.
const (
	ActionPlatformUserCreate        = "platform.user.create"
	ActionPlatformUserUpdate        = "platform.user.update"
	ActionPlatformUserTransition    = "platform.user.transition"
	ActionPlatformUserPasswordReset = "platform.user.password_reset"
	ActionPlatformUserRoleUpdate    = "platform.user.role_update"
	ResourceTypePlatformUser        = "platform_user"
)

// Platform-user service errors are mapped to stable HTTP outcomes by the handler.
var (
	ErrAdminForbidden         = errors.New("auth: platform user permission denied")
	ErrAdminInvalidInput      = errors.New("auth: invalid platform user input")
	ErrAdminInvalidStatus     = errors.New("auth: invalid platform user status")
	ErrAdminInvalidRole       = errors.New("auth: invalid tenant role")
	ErrAdminInvalidTransition = errors.New("auth: invalid platform user transition")
	ErrAdminSelfDisable       = errors.New("auth: cannot disable current user")
	ErrLastSystemAdmin        = errors.New("auth: cannot remove last active system administrator")
	ErrAdminUnavailable       = errors.New("auth: platform user service unavailable")
)

var platformUsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type adminAuditRecorder interface {
	Record(context.Context, audit.Event) error
}

// AdminUserService enforces tenant isolation, RBAC, lifecycle rules, and audit atomicity.
type AdminUserService struct {
	repo      AdminUserRepository
	users     UserRepository
	db        *sql.DB
	auditSink adminAuditRecorder
}

// AdminUserServiceOption configures transactional platform-user dependencies.
type AdminUserServiceOption func(*AdminUserService)

// WithAdminUserDB enables database transactions for account and audit writes.
func WithAdminUserDB(db *sql.DB) AdminUserServiceOption {
	return func(service *AdminUserService) { service.db = db }
}

// WithAdminUserAuditSink supplies the non-transactional audit sink used by tests.
func WithAdminUserAuditSink(sink adminAuditRecorder) AdminUserServiceOption {
	return func(service *AdminUserService) { service.auditSink = sink }
}

// NewAdminUserService creates the platform-user application service.
func NewAdminUserService(repo AdminUserRepository, users UserRepository, options ...AdminUserServiceOption) *AdminUserService {
	service := &AdminUserService{repo: repo, users: users}
	for _, option := range options {
		option(service)
	}
	return service
}

// List returns users from the authenticated actor's tenant only.
func (s *AdminUserService) List(ctx context.Context, actorID string, filter PlatformUserListFilter) (PlatformUserList, error) {
	actor, err := s.requirePermission(ctx, actorID, asmcasbin.PermUserRead)
	if err != nil {
		return PlatformUserList{}, err
	}
	filter.Search = strings.TrimSpace(filter.Search)
	filter.Status = strings.TrimSpace(filter.Status)
	filter.Role = strings.TrimSpace(filter.Role)
	if utf8.RuneCountInString(filter.Search) > 128 || !validStatusFilter(filter.Status) || !validRoleFilter(filter.Role) {
		return PlatformUserList{}, ErrAdminInvalidInput
	}
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 20
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	return s.repo.List(ctx, actor.TenantID, filter)
}

// Get returns one same-tenant platform user.
func (s *AdminUserService) Get(ctx context.Context, actorID string, userID uint64) (*PlatformUser, error) {
	actor, err := s.requirePermission(ctx, actorID, asmcasbin.PermUserRead)
	if err != nil {
		return nil, err
	}
	return s.repo.GetByTenantID(ctx, actor.TenantID, userID)
}

// ListProjects returns read-only project memberships for a same-tenant user.
func (s *AdminUserService) ListProjects(ctx context.Context, actorID string, userID uint64) ([]PlatformUserProject, error) {
	actor, err := s.requirePermission(ctx, actorID, asmcasbin.PermUserRead)
	if err != nil {
		return nil, err
	}
	if _, err := s.repo.GetByTenantID(ctx, actor.TenantID, userID); err != nil {
		return nil, err
	}
	return s.repo.ListProjects(ctx, actor.TenantID, userID)
}

// Roles returns the fixed read-only MVP role matrix.
func (s *AdminUserService) Roles(ctx context.Context, actorID string) ([]AdminRole, error) {
	if _, err := s.requirePermission(ctx, actorID, asmcasbin.PermUserRead); err != nil {
		return nil, err
	}
	roles := make([]AdminRole, 0, len(asmcasbin.AllRoles))
	for _, role := range asmcasbin.AllRoles {
		scope := "project"
		if validTenantRole(role) {
			scope = "tenant"
		}
		roles = append(roles, AdminRole{
			Value: role, Label: platformRoleLabel(role), Scope: scope,
			Permissions: asmcasbin.PermissionsForRole(role),
		})
	}
	return roles, nil
}

// Create provisions an account in the actor's tenant and organization.
func (s *AdminUserService) Create(ctx context.Context, in CreatePlatformUserInput) (*PlatformUser, error) {
	if err := normalizeCreatePlatformUser(&in); err != nil {
		return nil, err
	}
	actor, err := s.requirePermission(ctx, in.ActorID, asmcasbin.PermUserWrite)
	if err != nil {
		return nil, err
	}
	if in.Role != PlatformRoleNone {
		if _, err := s.requirePermission(ctx, in.ActorID, asmcasbin.PermUserRoleWrite); err != nil {
			return nil, err
		}
	}
	passwordHash, err := hashTemporaryPassword(in.Password)
	if err != nil {
		return nil, err
	}

	var createdID uint64
	err = s.runTx(ctx, func(repo AdminUserRepository, sink adminAuditRecorder) error {
		createdID, err = repo.Create(ctx, actor.TenantID, actor.OrgID, in, passwordHash)
		if err != nil {
			return err
		}
		if in.Role != PlatformRoleNone {
			if err := repo.UpsertTenantRole(ctx, actor.TenantID, createdID, in.Role, in.ActorID); err != nil {
				return err
			}
		}
		created, err := repo.GetByTenantID(ctx, actor.TenantID, createdID)
		if err != nil {
			return err
		}
		return recordAdminUserAudit(ctx, sink, actor, in.ActorID, ActionPlatformUserCreate, createdID, nil, created, in.Meta, "")
	})
	if err != nil {
		return nil, err
	}
	return s.repo.GetByTenantID(ctx, actor.TenantID, createdID)
}

// Update changes mutable profile fields without changing username or credentials.
func (s *AdminUserService) Update(ctx context.Context, in UpdatePlatformUserInput) (*PlatformUser, error) {
	actor, err := s.requirePermission(ctx, in.ActorID, asmcasbin.PermUserWrite)
	if err != nil {
		return nil, err
	}
	if in.DisplayName == nil && in.Email == nil && in.Phone == nil && in.Department == nil {
		return nil, ErrAdminInvalidInput
	}
	err = s.runTx(ctx, func(repo AdminUserRepository, sink adminAuditRecorder) error {
		before, err := repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
		if err != nil {
			return err
		}
		after := *before
		applyProfileUpdate(&after, in)
		if err := validateProfile(after.DisplayName, after.Email, after.Phone, after.Department); err != nil {
			return err
		}
		changed, err := repo.UpdateProfile(ctx, actor.TenantID, in, after)
		if err != nil {
			return err
		}
		if !changed {
			return ErrAdminUserNotFound
		}
		stored, err := repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
		if err != nil {
			return err
		}
		return recordAdminUserAudit(ctx, sink, actor, in.ActorID, ActionPlatformUserUpdate, in.UserID, before, stored, in.Meta, "")
	})
	if err != nil {
		return nil, err
	}
	return s.repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
}

// Transition enables or disables an account and revokes existing sessions.
func (s *AdminUserService) Transition(ctx context.Context, in TransitionPlatformUserInput) (*PlatformUser, error) {
	in.Status = strings.TrimSpace(in.Status)
	in.Reason = strings.TrimSpace(in.Reason)
	if !validPlatformUserStatus(in.Status) || in.Reason == "" || utf8.RuneCountInString(in.Reason) > 512 {
		return nil, ErrAdminInvalidInput
	}
	actor, err := s.requirePermission(ctx, in.ActorID, asmcasbin.PermUserWrite)
	if err != nil {
		return nil, err
	}
	actorNumericID, err := parseUserID(in.ActorID)
	if err != nil {
		return nil, ErrAdminForbidden
	}

	err = s.runTx(ctx, func(repo AdminUserRepository, sink adminAuditRecorder) error {
		before, err := repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
		if err != nil {
			return err
		}
		if before.Status == in.Status {
			return ErrAdminInvalidTransition
		}
		if in.Status == UserStatusDisabled && actorNumericID == in.UserID {
			return ErrAdminSelfDisable
		}
		if in.Status == UserStatusDisabled && before.Status == UserStatusActive && before.Role == PlatformRoleSystemAdmin {
			count, err := repo.CountActiveSystemAdmins(ctx, actor.TenantID)
			if err != nil {
				return err
			}
			if count <= 1 {
				return ErrLastSystemAdmin
			}
		}
		changed, err := repo.TransitionStatus(ctx, actor.TenantID, in.UserID, before.Status, in.Status, in.ActorID)
		if err != nil {
			return err
		}
		if !changed {
			return ErrAdminInvalidTransition
		}
		after, err := repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
		if err != nil {
			return err
		}
		return recordAdminUserAudit(ctx, sink, actor, in.ActorID, ActionPlatformUserTransition, in.UserID, before, after, in.Meta, in.Reason)
	})
	if err != nil {
		return nil, err
	}
	return s.repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
}

// ResetPassword stores a temporary bcrypt hash and revokes existing sessions.
func (s *AdminUserService) ResetPassword(ctx context.Context, in ResetPlatformUserPasswordInput) error {
	actor, err := s.requirePermission(ctx, in.ActorID, asmcasbin.PermUserCredentialReset)
	if err != nil {
		return err
	}
	passwordHash, err := hashTemporaryPassword(in.TemporaryPassword)
	if err != nil {
		return err
	}
	return s.runTx(ctx, func(repo AdminUserRepository, sink adminAuditRecorder) error {
		before, err := repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
		if err != nil {
			return err
		}
		changed, err := repo.ResetPassword(ctx, actor.TenantID, in.UserID, passwordHash, in.ActorID)
		if err != nil {
			return err
		}
		if !changed {
			return ErrAdminUserNotFound
		}
		after, err := repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
		if err != nil {
			return err
		}
		return recordAdminUserAudit(ctx, sink, actor, in.ActorID, ActionPlatformUserPasswordReset, in.UserID, before, after, in.Meta, "")
	})
}

// UpdateTenantRole sets or clears a platform role and revokes existing sessions.
func (s *AdminUserService) UpdateTenantRole(ctx context.Context, in UpdateTenantRoleInput) (*PlatformUser, error) {
	in.Role = strings.TrimSpace(in.Role)
	if in.Role != PlatformRoleNone && !validTenantRole(in.Role) {
		return nil, ErrAdminInvalidRole
	}
	actor, err := s.requirePermission(ctx, in.ActorID, asmcasbin.PermUserRoleWrite)
	if err != nil {
		return nil, err
	}
	err = s.runTx(ctx, func(repo AdminUserRepository, sink adminAuditRecorder) error {
		before, err := repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
		if err != nil {
			return err
		}
		if before.Role == in.Role {
			return nil
		}
		if before.Role == PlatformRoleSystemAdmin && in.Role != PlatformRoleSystemAdmin && before.Status == UserStatusActive {
			count, err := repo.CountActiveSystemAdmins(ctx, actor.TenantID)
			if err != nil {
				return err
			}
			if count <= 1 {
				return ErrLastSystemAdmin
			}
		}
		if in.Role == PlatformRoleNone {
			if err := repo.RemoveTenantRole(ctx, actor.TenantID, in.UserID, in.ActorID); err != nil {
				return err
			}
		} else if err := repo.UpsertTenantRole(ctx, actor.TenantID, in.UserID, in.Role, in.ActorID); err != nil {
			return err
		}
		changed, err := repo.IncrementAuthVersion(ctx, actor.TenantID, in.UserID, in.ActorID)
		if err != nil {
			return err
		}
		if !changed {
			return ErrAdminUserNotFound
		}
		after, err := repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
		if err != nil {
			return err
		}
		return recordAdminUserAudit(ctx, sink, actor, in.ActorID, ActionPlatformUserRoleUpdate, in.UserID, before, after, in.Meta, "")
	})
	if err != nil {
		return nil, err
	}
	return s.repo.GetByTenantID(ctx, actor.TenantID, in.UserID)
}

func (s *AdminUserService) requirePermission(ctx context.Context, actorID, permission string) (*User, error) {
	if s.users == nil || s.repo == nil {
		return nil, ErrAdminUnavailable
	}
	id, err := parseUserID(actorID)
	if err != nil || id == 0 {
		return nil, ErrAdminForbidden
	}
	actor, err := s.users.GetByID(ctx, id)
	if err != nil || !actor.IsActive() {
		return nil, ErrAdminForbidden
	}
	role, err := s.users.GetGlobalRole(ctx, id)
	if err != nil {
		return nil, err
	}
	if !asmcasbin.RoleHasPerm(role, permission) {
		return nil, ErrAdminForbidden
	}
	return actor, nil
}

func (s *AdminUserService) runTx(ctx context.Context, fn func(AdminUserRepository, adminAuditRecorder) error) error {
	if s.repo == nil {
		return ErrAdminUnavailable
	}
	if s.db == nil {
		if s.auditSink == nil {
			return ErrAdminUnavailable
		}
		return fn(s.repo, s.auditSink)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txRepo := NewAdminUserRepository(dbgen.New(tx))
	txAudit := audit.NewService(audit.NewRepository(dbgen.New(tx)))
	if err := fn(txRepo, txAudit); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func normalizeCreatePlatformUser(in *CreatePlatformUserInput) error {
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.Phone = strings.TrimSpace(in.Phone)
	in.Department = strings.TrimSpace(in.Department)
	in.Role = strings.TrimSpace(in.Role)
	in.Status = strings.TrimSpace(in.Status)
	if in.Status == "" {
		in.Status = UserStatusActive
	}
	if !platformUsernamePattern.MatchString(in.Username) || !validPlatformUserStatus(in.Status) {
		return ErrAdminInvalidInput
	}
	if in.Role != PlatformRoleNone && !validTenantRole(in.Role) {
		return ErrAdminInvalidRole
	}
	if err := validateProfile(in.DisplayName, in.Email, in.Phone, in.Department); err != nil {
		return err
	}
	return validateTemporaryPassword(in.Password)
}

func applyProfileUpdate(user *PlatformUser, in UpdatePlatformUserInput) {
	if in.DisplayName != nil {
		user.DisplayName = strings.TrimSpace(*in.DisplayName)
	}
	if in.Email != nil {
		user.Email = strings.ToLower(strings.TrimSpace(*in.Email))
	}
	if in.Phone != nil {
		user.Phone = strings.TrimSpace(*in.Phone)
	}
	if in.Department != nil {
		user.Department = strings.TrimSpace(*in.Department)
	}
}

func validateProfile(displayName, email, phone, department string) error {
	if displayName == "" || utf8.RuneCountInString(displayName) > 255 || utf8.RuneCountInString(email) > 255 ||
		utf8.RuneCountInString(phone) > 32 || utf8.RuneCountInString(department) > 128 {
		return ErrAdminInvalidInput
	}
	if email != "" {
		parsed, err := mail.ParseAddress(email)
		if err != nil || parsed.Address != email {
			return ErrAdminInvalidInput
		}
	}
	return nil
}

func validateTemporaryPassword(password string) error {
	length := len([]byte(password))
	if length < 12 || length > 72 {
		return ErrAdminInvalidInput
	}
	return nil
}

func hashTemporaryPassword(password string) (string, error) {
	if err := validateTemporaryPassword(password); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash temporary password: %w", err)
	}
	return string(hash), nil
}

func validPlatformUserStatus(status string) bool {
	return status == UserStatusActive || status == UserStatusDisabled
}

func validStatusFilter(status string) bool {
	return status == "" || validPlatformUserStatus(status)
}

func validTenantRole(role string) bool {
	return role == PlatformRoleSystemAdmin || role == PlatformRoleSecurityAdmin
}

func validRoleFilter(role string) bool {
	return role == "" || role == "none" || validTenantRole(role)
}

func platformRoleLabel(role string) string {
	switch role {
	case asmcasbin.RoleSystemAdmin:
		return "系统管理员"
	case asmcasbin.RoleSecurityAdmin:
		return "安全管理员"
	case asmcasbin.RoleProjectOwner:
		return "项目负责人"
	case asmcasbin.RoleSecurityOps:
		return "安全运营"
	case asmcasbin.RoleDeveloper:
		return "整改人员"
	case asmcasbin.RoleViewer:
		return "只读用户"
	default:
		return role
	}
}

func recordAdminUserAudit(
	ctx context.Context,
	sink adminAuditRecorder,
	actor *User,
	actorID, action string,
	resourceID uint64,
	before, after *PlatformUser,
	meta AdminAuditMeta,
	reason string,
) error {
	if sink == nil || actor == nil {
		return ErrAdminUnavailable
	}
	metadata := map[string]any{"actor_org_id": actor.OrgID}
	if reason != "" {
		metadata["reason"] = reason
	}
	targetOrgID := actor.OrgID
	if after != nil {
		targetOrgID = after.OrgID
	} else if before != nil {
		targetOrgID = before.OrgID
	}
	return sink.Record(ctx, audit.Event{
		TenantID: actor.TenantID, OrgID: targetOrgID, ActorID: actorID,
		ActorType: audit.ActorUser, Action: action, ResourceType: ResourceTypePlatformUser,
		ResourceID: fmt.Sprint(resourceID), Result: audit.ResultSuccess,
		IP: meta.IP, UserAgent: meta.UserAgent, RequestID: meta.RequestID,
		Before: safePlatformUserAuditSnapshot(before), After: safePlatformUserAuditSnapshot(after), Metadata: metadata,
	})
}

func safePlatformUserAuditSnapshot(user *PlatformUser) any {
	if user == nil {
		return nil
	}
	return map[string]any{
		"id": user.ID, "username": user.Username, "display_name": user.DisplayName,
		"org_id": user.OrgID,
		"email":  user.Email, "phone": user.Phone, "department": user.Department,
		"role": user.Role, "status": user.Status, "must_change_password": user.MustChangePassword,
	}
}
