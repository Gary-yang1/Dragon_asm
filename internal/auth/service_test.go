package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

// fakeUserRepo is an in-memory UserRepository keyed by username and id.
type fakeUserRepo struct {
	byName map[string]*auth.User
	byID   map[uint64]*auth.User
}

func newFakeUserRepo(users ...*auth.User) *fakeUserRepo {
	r := &fakeUserRepo{
		byName: make(map[string]*auth.User),
		byID:   make(map[uint64]*auth.User),
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

func (r *fakeUserRepo) GetByID(_ context.Context, id uint64) (*auth.User, error) {
	if u, ok := r.byID[id]; ok {
		return u, nil
	}
	return nil, auth.ErrUserNotFound
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
