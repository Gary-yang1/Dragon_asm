package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/casbin/casbin/v2"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Audit action names for authentication events. Kept as constants so the audit
// log uses a stable, greppable vocabulary.
const (
	ActionLogin = "auth.login"
	// #nosec G101 -- this is an audit action name, not a credential.
	ActionTokenRefresh = "auth.token_refresh"
	// #nosec G101 -- this is an audit action name, not a credential.
	ActionPasswordChange = "auth.password_change"
)

// ErrInvalidCredentials is the single error returned for every failed login —
// unknown username, wrong password, or disabled account all map to it, so the
// caller cannot distinguish them and no username-existence oracle is exposed.
var ErrInvalidCredentials = errors.New("auth: invalid credentials")

// ErrInvalidRefreshToken is returned when a refresh token is missing, malformed,
// expired, or references a user that is gone or disabled.
var ErrInvalidRefreshToken = errors.New("auth: invalid refresh token")

// ErrCurrentPasswordInvalid does not reveal any stored credential detail.
var ErrCurrentPasswordInvalid = errors.New("auth: current password is invalid")

// ErrPasswordUnchanged rejects replacing a password with the same value.
var ErrPasswordUnchanged = errors.New("auth: new password must differ")

// ErrPasswordInvalid indicates that the replacement password does not meet the
// platform password policy, without exposing which stored credential was used.
var ErrPasswordInvalid = errors.New("auth: invalid new password")

// RequestMeta carries request-scoped context for audit logging. The service
// never reads secrets from it; it exists only to enrich the audit trail.
type RequestMeta struct {
	IP        string
	UserAgent string
	RequestID string
}

// auditRecorder is the minimal audit sink the service depends on. *audit.Service
// satisfies it. A nil recorder disables audit writes (used in unit tests that
// assert only on the auth decision).
type auditRecorder interface {
	Record(ctx context.Context, e audit.Event) error
}

type successfulLoginRecorder interface {
	RecordSuccessfulLogin(ctx context.Context, id uint64) error
}

// TokenPair is the successful result of a login or refresh.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// LoginSession is the HTTP login payload model: tokens plus the default web
// project context. Tokens stay separate from the user profile to keep secrets
// out of nested structures that may be logged by callers.
type LoginSession struct {
	TokenPair   TokenPair
	User        *User
	Membership  *ProjectMembership
	Permissions []string
}

// Service implements the authentication use cases: login, token refresh, current
// user lookup, and permission enumeration. It writes an audit_log entry for
// login (success and failure) and for refresh failures.
type Service struct {
	repo     UserRepository
	tokens   *JWTManager
	enforcer *casbin.Enforcer
	audit    auditRecorder
	db       *sql.DB
}

// ServiceOption configures authentication flows that require transactions.
type ServiceOption func(*Service)

// WithAuthDB enables atomic password-change and audit writes.
func WithAuthDB(db *sql.DB) ServiceOption {
	return func(service *Service) { service.db = db }
}

// NewService builds an auth Service. enforcer may be nil only in tests that do
// not exercise Permissions; audit may be nil to disable audit writes.
func NewService(repo UserRepository, tokens *JWTManager, enforcer *casbin.Enforcer, auditSvc auditRecorder, options ...ServiceOption) *Service {
	service := &Service{repo: repo, tokens: tokens, enforcer: enforcer, audit: auditSvc}
	for _, option := range options {
		option(service)
	}
	return service
}

// ChangePassword verifies the current credential, replaces it with a bcrypt
// hash, clears the temporary-password flag, revokes existing sessions, and
// records the mutation atomically. Password values never enter the audit event.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string, meta RequestMeta) error {
	id, err := parseUserID(userID)
	if err != nil {
		return ErrUserNotFound
	}
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if !user.IsActive() {
		return ErrUserNotFound
	}
	if !CheckPassword(user.PasswordHash, currentPassword) {
		s.recordPasswordChangeFailure(ctx, user, meta, "current_password_invalid")
		return ErrCurrentPasswordInvalid
	}
	if CheckPassword(user.PasswordHash, newPassword) {
		s.recordPasswordChangeFailure(ctx, user, meta, "password_unchanged")
		return ErrPasswordUnchanged
	}
	if err := validateTemporaryPassword(newPassword); err != nil {
		return ErrPasswordInvalid
	}
	passwordHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	err = s.runPasswordChangeTx(ctx, func(repo UserRepository, sink auditRecorder) error {
		before, err := repo.GetByID(ctx, id)
		if err != nil || !before.IsActive() {
			return ErrUserNotFound
		}
		if !CheckPassword(before.PasswordHash, currentPassword) {
			return ErrCurrentPasswordInvalid
		}
		credentials, ok := repo.(currentPasswordRepository)
		if !ok {
			return errors.New("auth: password repository unavailable")
		}
		changed, err := credentials.ChangeCurrentPassword(ctx, before.TenantID, id, passwordHash, userID)
		if err != nil {
			return err
		}
		if !changed {
			return ErrUserNotFound
		}
		after := *before
		after.MustChangePassword = false
		after.AuthVersion++
		return sink.Record(ctx, audit.Event{
			TenantID: before.TenantID, OrgID: before.OrgID,
			ActorID: userID, ActorType: audit.ActorUser,
			Action: ActionPasswordChange, ResourceType: "user", ResourceID: userID,
			Result: audit.ResultSuccess, IP: meta.IP, UserAgent: meta.UserAgent, RequestID: meta.RequestID,
			Before: passwordAuditSnapshot(before), After: passwordAuditSnapshot(&after),
		})
	})
	if errors.Is(err, ErrCurrentPasswordInvalid) {
		s.recordPasswordChangeFailure(ctx, user, meta, "current_password_changed_concurrently")
	}
	return err
}

func (s *Service) runPasswordChangeTx(ctx context.Context, fn func(UserRepository, auditRecorder) error) error {
	if s.db == nil {
		if s.repo == nil || s.audit == nil {
			return errors.New("auth: password change unavailable")
		}
		return fn(s.repo, s.audit)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	repo := NewUserRepository(dbgen.New(tx))
	sink := audit.NewService(audit.NewRepository(dbgen.New(tx)))
	if err := fn(repo, sink); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Service) recordPasswordChangeFailure(ctx context.Context, user *User, meta RequestMeta, reason string) {
	if s.audit == nil || user == nil {
		return
	}
	_ = s.audit.Record(ctx, audit.Event{
		TenantID: user.TenantID, OrgID: user.OrgID,
		ActorID: actorID(user.ID), ActorType: audit.ActorUser,
		Action: ActionPasswordChange, ResourceType: "user", ResourceID: actorID(user.ID),
		Result: audit.ResultFailure, IP: meta.IP, UserAgent: meta.UserAgent, RequestID: meta.RequestID,
		Metadata: map[string]any{"reason": reason},
	})
}

func passwordAuditSnapshot(user *User) map[string]any {
	return map[string]any{
		"id":                   user.ID,
		"must_change_password": user.MustChangePassword,
		"auth_version":         user.AuthVersion,
	}
}

// Login verifies the username/password and, on success, issues an access +
// refresh token pair. Every failure returns ErrInvalidCredentials with no
// distinguishing detail. Audit is written for both outcomes; audit metadata
// never contains the password or any token.
//
// An unknown username still triggers a bcrypt comparison against a dummy hash so
// the "no such user" and "wrong password" paths cost roughly the same, blunting
// timing-based username enumeration.
func (s *Service) Login(ctx context.Context, username, password string, meta RequestMeta) (*TokenPair, error) {
	user, err := s.repo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			CheckPassword(dummyHash, password) // equalize timing; result ignored
			s.recordLogin(ctx, "", username, meta, false, "user_not_found")
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if !CheckPassword(user.PasswordHash, password) {
		s.recordLogin(ctx, actorID(user.ID), username, meta, false, "bad_password")
		return nil, ErrInvalidCredentials
	}

	if !user.IsActive() {
		s.recordLogin(ctx, actorID(user.ID), username, meta, false, "user_disabled")
		return nil, ErrInvalidCredentials
	}
	if recorder, ok := s.repo.(successfulLoginRecorder); ok {
		if err := recorder.RecordSuccessfulLogin(ctx, user.ID); err != nil {
			return nil, err
		}
	}

	pair, err := s.issuePair(user.ID, user.AuthVersion)
	if err != nil {
		return nil, err
	}
	s.recordLogin(ctx, actorID(user.ID), username, meta, true, "")
	return pair, nil
}

// LoginSession verifies credentials and returns the web shell's initial auth
// state in one round-trip. The default project is the user's first live project
// membership. Users without a project may still authenticate, but they receive
// no project role or derived permissions.
func (s *Service) LoginSession(ctx context.Context, username, password string, meta RequestMeta) (*LoginSession, error) {
	pair, err := s.Login(ctx, username, password, meta)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	membership, err := s.repo.GetDefaultProjectMembership(ctx, actorID(user.ID))
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}

	perms := []string{}
	if membership != nil {
		perms = s.permissionsForRole(membership.Role)
	}
	globalRole, err := s.repo.GetGlobalRole(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	perms = mergePermissions(perms, s.permissionsForRole(globalRole))

	return &LoginSession{
		TokenPair:   *pair,
		User:        user,
		Membership:  membership,
		Permissions: perms,
	}, nil
}

// Refresh validates a refresh token and re-issues a fresh access + refresh
// pair. The referenced user must still exist and be active. Failures return
// ErrInvalidRefreshToken and are audited; success is not audited here (it is a
// routine, low-signal event). Note: the old refresh token is not server-side
// revoked in this milestone.
func (s *Service) Refresh(ctx context.Context, refreshToken string, meta RequestMeta) (*TokenPair, error) {
	claims, err := s.tokens.ParseRefreshToken(refreshToken)
	if err != nil {
		s.recordRefreshFailure(ctx, "", meta, "invalid_token")
		return nil, ErrInvalidRefreshToken
	}

	id, err := parseUserID(claims.UserID)
	if err != nil {
		s.recordRefreshFailure(ctx, claims.UserID, meta, "malformed_subject")
		return nil, ErrInvalidRefreshToken
	}

	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.recordRefreshFailure(ctx, claims.UserID, meta, "user_not_found")
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}
	if !user.IsActive() {
		s.recordRefreshFailure(ctx, actorID(user.ID), meta, "user_disabled")
		return nil, ErrInvalidRefreshToken
	}
	if claims.AuthVersion != user.AuthVersion {
		s.recordRefreshFailure(ctx, actorID(user.ID), meta, "auth_version_mismatch")
		return nil, ErrInvalidRefreshToken
	}

	return s.issuePair(user.ID, user.AuthVersion)
}

// Me returns the live user for the authenticated id, or ErrUserNotFound.
func (s *Service) Me(ctx context.Context, userID string) (*User, error) {
	id, err := parseUserID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return s.repo.GetByID(ctx, id)
}

// Permissions returns the distinct permission points (the object component of
// each Casbin policy) the user holds, across every domain, including those
// inherited via role assignments. The result is deterministic (sorted, unique).
func (s *Service) Permissions(ctx context.Context, userID string) ([]string, error) {
	if _, err := parseUserID(userID); err != nil {
		return nil, ErrUserNotFound
	}
	// Confirm the user still exists/authorizes before reporting permissions.
	user, err := s.Me(ctx, userID)
	if err != nil {
		return nil, err
	}

	policies, err := s.enforcer.GetImplicitPermissionsForUser(userID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(policies))
	for _, p := range policies {
		// Policy layout is (sub, dom, obj, act); obj is the permission point.
		if len(p) < 3 {
			continue
		}
		out = append(out, p[2])
	}
	membership, err := s.repo.GetDefaultProjectMembership(ctx, userID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}
	if membership != nil {
		out = append(out, s.permissionsForRole(membership.Role)...)
	}
	globalRole, err := s.repo.GetGlobalRole(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	out = append(out, s.permissionsForRole(globalRole)...)
	return mergePermissions(out), nil
}

func (s *Service) permissionsForRole(role string) []string {
	if s.enforcer == nil || role == "" {
		return nil
	}
	policies, err := s.enforcer.GetPermissionsForUser(role)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(policies))
	out := make([]string, 0, len(policies))
	for _, p := range policies {
		if len(p) < 3 {
			continue
		}
		obj := p[2]
		if _, dup := seen[obj]; dup {
			continue
		}
		seen[obj] = struct{}{}
		out = append(out, obj)
	}
	sortStrings(out)
	return out
}

func mergePermissions(groups ...[]string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, group := range groups {
		for _, permission := range group {
			if _, duplicate := seen[permission]; duplicate {
				continue
			}
			seen[permission] = struct{}{}
			out = append(out, permission)
		}
	}
	sortStrings(out)
	return out
}

func (s *Service) issuePair(userID uint64, authVersion uint32) (*TokenPair, error) {
	sub := actorID(userID)
	access, err := s.tokens.IssueAccessToken(sub, authVersion)
	if err != nil {
		return nil, err
	}
	refresh, err := s.tokens.IssueRefreshToken(sub, authVersion)
	if err != nil {
		return nil, err
	}
	return &TokenPair{AccessToken: access, RefreshToken: refresh}, nil
}

// recordLogin writes a login audit event. metadata carries only a coarse reason
// code and the attempted username — never the password or any token. Audit
// failures are swallowed: an audit outage must not block or leak into the login
// response.
func (s *Service) recordLogin(ctx context.Context, actor, username string, meta RequestMeta, success bool, reason string) {
	if s.audit == nil {
		return
	}
	result := audit.ResultFailure
	if success {
		result = audit.ResultSuccess
	}
	md := map[string]any{"username": username}
	if reason != "" {
		md["reason"] = reason
	}
	_ = s.audit.Record(ctx, audit.Event{
		ActorID:      actor,
		ActorType:    audit.ActorUser,
		Action:       ActionLogin,
		ResourceType: "user",
		ResourceID:   actor,
		Result:       result,
		IP:           meta.IP,
		UserAgent:    meta.UserAgent,
		RequestID:    meta.RequestID,
		Metadata:     md,
	})
}

func (s *Service) recordRefreshFailure(ctx context.Context, actor string, meta RequestMeta, reason string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, audit.Event{
		ActorID:      actor,
		ActorType:    audit.ActorUser,
		Action:       ActionTokenRefresh,
		ResourceType: "user",
		ResourceID:   actor,
		Result:       audit.ResultFailure,
		IP:           meta.IP,
		UserAgent:    meta.UserAgent,
		RequestID:    meta.RequestID,
		Metadata:     map[string]any{"reason": reason},
	})
}
