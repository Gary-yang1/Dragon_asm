package auth

import (
	"context"
	"errors"

	"github.com/casbin/casbin/v2"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

// Audit action names for authentication events. Kept as constants so the audit
// log uses a stable, greppable vocabulary.
const (
	ActionLogin = "auth.login"
	// #nosec G101 -- this is an audit action name, not a credential.
	ActionTokenRefresh = "auth.token_refresh"
)

// ErrInvalidCredentials is the single error returned for every failed login —
// unknown username, wrong password, or disabled account all map to it, so the
// caller cannot distinguish them and no username-existence oracle is exposed.
var ErrInvalidCredentials = errors.New("auth: invalid credentials")

// ErrInvalidRefreshToken is returned when a refresh token is missing, malformed,
// expired, or references a user that is gone or disabled.
var ErrInvalidRefreshToken = errors.New("auth: invalid refresh token")

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

// TokenPair is the successful result of a login or refresh.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// Service implements the authentication use cases: login, token refresh, current
// user lookup, and permission enumeration. It writes an audit_log entry for
// login (success and failure) and for refresh failures.
type Service struct {
	repo     UserRepository
	tokens   *JWTManager
	enforcer *casbin.Enforcer
	audit    auditRecorder
}

// NewService builds an auth Service. enforcer may be nil only in tests that do
// not exercise Permissions; audit may be nil to disable audit writes.
func NewService(repo UserRepository, tokens *JWTManager, enforcer *casbin.Enforcer, auditSvc auditRecorder) *Service {
	return &Service{repo: repo, tokens: tokens, enforcer: enforcer, audit: auditSvc}
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

	pair, err := s.issuePair(user.ID)
	if err != nil {
		return nil, err
	}
	s.recordLogin(ctx, actorID(user.ID), username, meta, true, "")
	return pair, nil
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

	return s.issuePair(user.ID)
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
	if _, err := s.Me(ctx, userID); err != nil {
		return nil, err
	}

	perms, err := s.enforcer.GetImplicitPermissionsForUser(userID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(perms))
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		// Policy layout is (sub, dom, obj, act); obj is the permission point.
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
	return out, nil
}

func (s *Service) issuePair(userID uint64) (*TokenPair, error) {
	sub := actorID(userID)
	access, err := s.tokens.IssueAccessToken(sub)
	if err != nil {
		return nil, err
	}
	refresh, err := s.tokens.IssueRefreshToken(sub)
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
