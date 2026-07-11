package auth_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

// fakeUserRepo is an in-memory UserRepository keyed by username and id.
type fakeUserRepo struct {
	byName      map[string]*auth.User
	byID        map[uint64]*auth.User
	memberships map[string]*auth.ProjectMembership
	globalRoles map[uint64]string
	loginIDs    []uint64
}

func (r *fakeUserRepo) RecordSuccessfulLogin(_ context.Context, userID uint64) error {
	r.loginIDs = append(r.loginIDs, userID)
	return nil
}

func newFakeUserRepo(users ...*auth.User) *fakeUserRepo {
	r := &fakeUserRepo{
		byName:      make(map[string]*auth.User),
		byID:        make(map[uint64]*auth.User),
		memberships: make(map[string]*auth.ProjectMembership),
		globalRoles: make(map[uint64]string),
	}
	for _, u := range users {
		r.byName[u.Username] = u
		r.byID[u.ID] = u
	}
	return r
}

func (r *fakeUserRepo) GetByUsername(_ context.Context, username string) (*auth.User, error) {
	if u, ok := r.byName[username]; ok {
		return u, nil
	}
	return nil, auth.ErrUserNotFound
}

func (r *fakeUserRepo) GetDefaultProjectMembership(_ context.Context, userID string) (*auth.ProjectMembership, error) {
	if m, ok := r.memberships[userID]; ok {
		return m, nil
	}
	return nil, auth.ErrUserNotFound
}

func (r *fakeUserRepo) withMembership(userID string, projectID uint64, role string) *fakeUserRepo {
	r.memberships[userID] = &auth.ProjectMembership{ProjectID: projectID, Role: role}
	return r
}

func (r *fakeUserRepo) GetGlobalRole(_ context.Context, userID uint64) (string, error) {
	return r.globalRoles[userID], nil
}

func (r *fakeUserRepo) withGlobalRole(userID uint64, role string) *fakeUserRepo {
	r.globalRoles[userID] = role
	return r
}

func (r *fakeUserRepo) GetByID(_ context.Context, id uint64) (*auth.User, error) {
	if u, ok := r.byID[id]; ok {
		return u, nil
	}
	return nil, auth.ErrUserNotFound
}

func (r *fakeUserRepo) ChangeCurrentPassword(_ context.Context, tenantID string, userID uint64, passwordHash, _ string) (bool, error) {
	u, ok := r.byID[userID]
	if !ok || u.TenantID != tenantID || u.Status != auth.UserStatusActive {
		return false, nil
	}
	u.PasswordHash = passwordHash
	u.MustChangePassword = false
	u.AuthVersion++
	return true, nil
}

// capturingAuditRepo records inserted audit events so tests can assert on them.
type capturingAuditRepo struct{ events []audit.Event }

func (c *capturingAuditRepo) Insert(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return nil
}

// mustUser builds an active user with the given username/password.
func mustUser(t *testing.T, id uint64, username, password string) *auth.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	require.NoError(t, err)
	return &auth.User{
		ID:           id,
		TenantID:     "t1",
		OrgID:        "o1",
		Username:     username,
		DisplayName:  username,
		PasswordHash: hash,
		AuthVersion:  1,
		Status:       auth.UserStatusActive,
	}
}

func newAuthService(t *testing.T, repo auth.UserRepository) (*auth.Service, *capturingAuditRepo) {
	t.Helper()
	auditRepo := &capturingAuditRepo{}
	svc := auth.NewService(repo, testManager(t), newEnforcer(t), audit.NewService(auditRepo))
	return svc, auditRepo
}

// Acceptance: login succeeds with correct credentials and returns a token pair;
// a success audit event is written and carries no password/token.
func TestLoginSuccess(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass"))
	svc, auditRepo := newAuthService(t, repo)

	pair, err := svc.Login(context.Background(), "admin", "s3cret-pass", auth.RequestMeta{IP: "10.0.0.1"})
	require.NoError(t, err)
	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)

	require.Len(t, auditRepo.events, 1)
	ev := auditRepo.events[0]
	assert.Equal(t, auth.ActionLogin, ev.Action)
	assert.Equal(t, audit.ResultSuccess, ev.Result)
	assert.Equal(t, "1", ev.ActorID)
	assertNoSecretInAudit(t, ev, "s3cret-pass", pair.AccessToken, pair.RefreshToken)
	assert.Equal(t, []uint64{1}, repo.loginIDs)
}

func TestLoginSessionIncludesDefaultProjectRoleAndPermissions(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass")).
		withMembership("1", 7, asmcasbin.RoleProjectOwner)
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	require.NoError(t, asmcasbin.SeedMVPolicies(e))
	svc := auth.NewService(repo, testManager(t), e, audit.NewService(&capturingAuditRepo{}))

	session, err := svc.LoginSession(context.Background(), "admin", "s3cret-pass", auth.RequestMeta{})
	require.NoError(t, err)

	assert.NotEmpty(t, session.TokenPair.AccessToken)
	require.NotNil(t, session.User)
	require.NotNil(t, session.Membership)
	assert.Equal(t, uint64(7), session.Membership.ProjectID)
	assert.Equal(t, asmcasbin.RoleProjectOwner, session.Membership.Role)
	assert.Contains(t, session.Permissions, asmcasbin.PermAssetRead)
	assert.Contains(t, session.Permissions, asmcasbin.PermRiskWrite)
	assert.NotContains(t, session.Permissions, asmcasbin.PermAdminManage)
}

// Acceptance: an unknown username yields ErrInvalidCredentials (indistinguishable
// from a wrong password) and a failure audit event.
func TestLoginUnknownUser(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass"))
	svc, auditRepo := newAuthService(t, repo)

	_, err := svc.Login(context.Background(), "ghost", "whatever", auth.RequestMeta{})
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)

	require.Len(t, auditRepo.events, 1)
	assert.Equal(t, audit.ResultFailure, auditRepo.events[0].Result)
}

// Acceptance: a wrong password yields the same ErrInvalidCredentials.
func TestLoginWrongPassword(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass"))
	svc, auditRepo := newAuthService(t, repo)

	_, err := svc.Login(context.Background(), "admin", "wrong", auth.RequestMeta{})
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	require.Len(t, auditRepo.events, 1)
	assert.Equal(t, audit.ResultFailure, auditRepo.events[0].Result)
	assertNoSecretInAudit(t, auditRepo.events[0], "wrong")
}

// Acceptance: a disabled user cannot log in even with the correct password.
func TestLoginDisabledUser(t *testing.T) {
	u := mustUser(t, 2, "bob", "pw-correct")
	u.Status = auth.UserStatusDisabled
	repo := newFakeUserRepo(u)
	svc, auditRepo := newAuthService(t, repo)

	_, err := svc.Login(context.Background(), "bob", "pw-correct", auth.RequestMeta{})
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	require.Len(t, auditRepo.events, 1)
	assert.Equal(t, audit.ResultFailure, auditRepo.events[0].Result)
}

// Acceptance: a refresh token issued at login can be exchanged for a fresh pair.
func TestRefreshSuccess(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass"))
	svc, _ := newAuthService(t, repo)

	pair, err := svc.Login(context.Background(), "admin", "s3cret-pass", auth.RequestMeta{})
	require.NoError(t, err)

	next, err := svc.Refresh(context.Background(), pair.RefreshToken, auth.RequestMeta{})
	require.NoError(t, err)
	assert.NotEmpty(t, next.AccessToken)
	assert.NotEmpty(t, next.RefreshToken)
}

func TestChangePasswordClearsFlagRevokesRefreshAndAuditsWithoutSecrets(t *testing.T) {
	user := mustUser(t, 1, "admin", "Temporary-123")
	user.MustChangePassword = true
	repo := newFakeUserRepo(user)
	svc, auditRepo := newAuthService(t, repo)

	pair, err := svc.Login(context.Background(), "admin", "Temporary-123", auth.RequestMeta{})
	require.NoError(t, err)

	err = svc.ChangePassword(context.Background(), "1", "Temporary-123", "Replacement-456", auth.RequestMeta{RequestID: "req-change"})
	require.NoError(t, err)
	assert.False(t, user.MustChangePassword)
	assert.Equal(t, uint32(2), user.AuthVersion)
	assert.True(t, auth.CheckPassword(user.PasswordHash, "Replacement-456"))
	assert.False(t, auth.CheckPassword(user.PasswordHash, "Temporary-123"))

	_, err = svc.Refresh(context.Background(), pair.RefreshToken, auth.RequestMeta{})
	require.ErrorIs(t, err, auth.ErrInvalidRefreshToken)
	require.Len(t, auditRepo.events, 3) // login, password change, rejected refresh
	change := auditRepo.events[1]
	assert.Equal(t, auth.ActionPasswordChange, change.Action)
	assert.Equal(t, audit.ResultSuccess, change.Result)
	assert.Equal(t, "req-change", change.RequestID)
	assert.NotContains(t, fmt.Sprint(change), "Temporary-123")
	assert.NotContains(t, fmt.Sprint(change), "Replacement-456")
}

func TestChangePasswordRejectsInvalidCurrentAndPolicy(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "Temporary-123"))
	svc, auditRepo := newAuthService(t, repo)

	err := svc.ChangePassword(context.Background(), "1", "wrong", "Replacement-456", auth.RequestMeta{})
	require.ErrorIs(t, err, auth.ErrCurrentPasswordInvalid)
	require.Len(t, auditRepo.events, 1)
	assert.Equal(t, audit.ResultFailure, auditRepo.events[0].Result)

	err = svc.ChangePassword(context.Background(), "1", "Temporary-123", "short", auth.RequestMeta{})
	require.ErrorIs(t, err, auth.ErrPasswordInvalid)
	assert.Equal(t, uint32(1), repo.byID[1].AuthVersion)
}

// An access token must not be accepted by the refresh endpoint (distinct secrets).
func TestRefreshRejectsAccessToken(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass"))
	svc, auditRepo := newAuthService(t, repo)

	pair, err := svc.Login(context.Background(), "admin", "s3cret-pass", auth.RequestMeta{})
	require.NoError(t, err)

	_, err = svc.Refresh(context.Background(), pair.AccessToken, auth.RequestMeta{})
	require.ErrorIs(t, err, auth.ErrInvalidRefreshToken)

	// login success + refresh failure.
	require.Len(t, auditRepo.events, 2)
	assert.Equal(t, auth.ActionTokenRefresh, auditRepo.events[1].Action)
	assert.Equal(t, audit.ResultFailure, auditRepo.events[1].Result)
}

// A refresh token whose user is now disabled must be rejected.
func TestRefreshDisabledUser(t *testing.T) {
	u := mustUser(t, 3, "carol", "pw")
	repo := newFakeUserRepo(u)
	svc, _ := newAuthService(t, repo)

	pair, err := svc.Login(context.Background(), "carol", "pw", auth.RequestMeta{})
	require.NoError(t, err)

	u.Status = auth.UserStatusDisabled
	_, err = svc.Refresh(context.Background(), pair.RefreshToken, auth.RequestMeta{})
	require.ErrorIs(t, err, auth.ErrInvalidRefreshToken)
}

// Me returns the live user for a valid subject and ErrUserNotFound otherwise.
func TestMe(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "pw"))
	svc, _ := newAuthService(t, repo)

	u, err := svc.Me(context.Background(), "1")
	require.NoError(t, err)
	assert.Equal(t, "admin", u.Username)

	_, err = svc.Me(context.Background(), "999")
	require.ErrorIs(t, err, auth.ErrUserNotFound)

	_, err = svc.Me(context.Background(), "not-numeric")
	require.ErrorIs(t, err, auth.ErrUserNotFound)
}

// Permissions returns the deduplicated, sorted permission points for the user.
// The subject is the numeric user id string, matching how the auth service
// issues Casbin subjects.
func TestPermissions(t *testing.T) {
	u := mustUser(t, 1, "alice-user", "pw")
	repo := newFakeUserRepo(u)

	// Subject "1" holds risk:read and asset:read directly, with a duplicate
	// asset:read grant in another domain to prove deduplication.
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	_, err = e.AddPolicy("1", "p1", asmcasbin.PermRiskRead, "allow")
	require.NoError(t, err)
	_, err = e.AddPolicy("1", "p1", asmcasbin.PermAssetRead, "allow")
	require.NoError(t, err)
	_, err = e.AddPolicy("1", "p2", asmcasbin.PermAssetRead, "allow") // duplicate obj, other domain
	require.NoError(t, err)

	svc := auth.NewService(repo, testManager(t), e, audit.NewService(&capturingAuditRepo{}))

	perms, err := svc.Permissions(context.Background(), "1")
	require.NoError(t, err)
	assert.Equal(t, []string{asmcasbin.PermAssetRead, asmcasbin.PermRiskRead}, perms,
		"permissions must be deduplicated and sorted")
}

// Permissions for a non-existent (but numeric) subject fails as unauthenticated.
func TestPermissionsUnknownUser(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "pw"))
	svc, _ := newAuthService(t, repo)

	_, err := svc.Permissions(context.Background(), "999")
	require.ErrorIs(t, err, auth.ErrUserNotFound)
}

func TestPermissionsIncludesBackendResolvedGlobalRole(t *testing.T) {
	u := mustUser(t, 1, "security-admin", "pw")
	repo := newFakeUserRepo(u).withGlobalRole(1, asmcasbin.RoleSecurityAdmin)
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	require.NoError(t, asmcasbin.SeedMVPolicies(e))
	svc := auth.NewService(repo, testManager(t), e, audit.NewService(&capturingAuditRepo{}))

	perms, err := svc.Permissions(context.Background(), "1")
	require.NoError(t, err)
	assert.Contains(t, perms, asmcasbin.PermProjectRead)
	assert.Contains(t, perms, asmcasbin.PermProjectCreate)
	assert.NotContains(t, perms, asmcasbin.PermAdminManage)
}

// assertNoSecretInAudit fails if any captured audit field contains a secret.
func assertNoSecretInAudit(t *testing.T, ev audit.Event, secrets ...string) {
	t.Helper()
	// Metadata is the only free-form field the service populates; ensure it
	// never carries a password or token value.
	md, _ := ev.Metadata.(map[string]any)
	for _, s := range secrets {
		if s == "" {
			continue
		}
		for k, v := range md {
			if str, ok := v.(string); ok {
				assert.NotContains(t, str, s, "audit metadata %q must not contain secret", k)
			}
		}
	}
}
