package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
)

// 64-byte test secrets (well above the 32-byte minimum). Not real secrets.
const (
	testAccessSecret  = "test-access-secret-0123456789abcdef0123456789abcdef"
	testRefreshSecret = "test-refresh-secret-0123456789abcdef0123456789abcdef"
)

func testManager(t *testing.T) *auth.JWTManager {
	t.Helper()
	m, err := auth.NewManager(auth.Config{
		AccessSecret:  testAccessSecret,
		RefreshSecret: testRefreshSecret,
	})
	require.NoError(t, err)
	return m
}

func TestNewManagerRejectsShortSecret(t *testing.T) {
	_, err := auth.NewManager(auth.Config{AccessSecret: "short", RefreshSecret: testRefreshSecret})
	require.ErrorIs(t, err, auth.ErrSecretTooShort)

	_, err = auth.NewManager(auth.Config{AccessSecret: testAccessSecret, RefreshSecret: "short"})
	require.ErrorIs(t, err, auth.ErrSecretTooShort)
}

func TestIssueAndParseAccessToken(t *testing.T) {
	m := testManager(t)

	tok, err := m.IssueAccessToken("alice", 1)
	require.NoError(t, err)
	require.NotEmpty(t, tok)

	claims, err := m.ParseAccessToken(tok)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.UserID)
	assert.NotNil(t, claims.ExpiresAt, "access token must carry an expiry")
}

func TestAccessAndRefreshSecretsAreDistinct(t *testing.T) {
	m := testManager(t)

	refresh, err := m.IssueRefreshToken("alice", 1)
	require.NoError(t, err)

	// A refresh token (signed with the refresh secret) must not validate as access.
	_, err = m.ParseAccessToken(refresh)
	require.Error(t, err, "refresh token must fail access verification")

	// It validates via the refresh path.
	_, err = m.ParseRefreshToken(refresh)
	require.NoError(t, err)
}

func TestExpiredTokenRejected(t *testing.T) {
	// Negative TTL mints a token whose expiry is already in the past.
	m, err := auth.NewManager(auth.Config{
		AccessSecret:  testAccessSecret,
		RefreshSecret: testRefreshSecret,
		AccessTTL:     -1 * time.Second,
	})
	require.NoError(t, err)

	tok, err := m.IssueAccessToken("alice", 1)
	require.NoError(t, err)

	_, err = m.ParseAccessToken(tok)
	require.Error(t, err, "expired token must be rejected")
}

func TestTamperedSignatureRejected(t *testing.T) {
	m := testManager(t)
	tok, err := m.IssueAccessToken("alice", 1)
	require.NoError(t, err)

	// Drop the final signature byte -> HMAC no longer matches.
	tampered := tok[:len(tok)-1]
	_, err = m.ParseAccessToken(tampered)
	require.Error(t, err, "tampered token must be rejected")
}

func TestWrongSecretRejected(t *testing.T) {
	mA := testManager(t)
	mB, err := auth.NewManager(auth.Config{
		AccessSecret:  "another-access-secret-0123456789abcdef0123456789",
		RefreshSecret: testRefreshSecret,
	})
	require.NoError(t, err)

	tok, err := mA.IssueAccessToken("alice", 1)
	require.NoError(t, err)

	_, err = mB.ParseAccessToken(tok)
	require.Error(t, err, "token signed by a different secret must be rejected")
}

func TestAlgorithmConfusionRejected(t *testing.T) {
	// Forge an alg=none token directly; it must not validate against the HMAC manager.
	claims := struct {
		UserID string `json:"uid"`
		jwt.RegisteredClaims
	}{UserID: "evil"}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	m := testManager(t)
	_, err = m.ParseAccessToken(tok)
	require.Error(t, err, "alg=none token must be rejected")
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("JWT_ACCESS_SECRET", strings.Repeat("a", 40))
	t.Setenv("JWT_REFRESH_SECRET", strings.Repeat("b", 40))
	t.Setenv("JWT_ACCESS_TTL", "30m")

	cfg, err := auth.LoadConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Minute, cfg.AccessTTL)
	assert.Equal(t, auth.DefaultRefreshTTL, cfg.RefreshTTL) // unset -> default
}

func TestLoadConfigFromEnvMissing(t *testing.T) {
	t.Setenv("JWT_ACCESS_SECRET", "")
	t.Setenv("JWT_REFRESH_SECRET", strings.Repeat("b", 40))

	_, err := auth.LoadConfigFromEnv()
	require.ErrorIs(t, err, auth.ErrSecretRequired)
}

func TestNewManagerRejectsIdenticalSecrets(t *testing.T) {
	same := strings.Repeat("a", 40) // long enough to pass the length check
	_, err := auth.NewManager(auth.Config{AccessSecret: same, RefreshSecret: same})
	require.ErrorIs(t, err, auth.ErrSecretsMustDiffer)
}

func TestIssueRejectsEmptyUserID(t *testing.T) {
	m := testManager(t)

	_, err := m.IssueAccessToken("", 1)
	require.ErrorIs(t, err, auth.ErrEmptyUserID)

	_, err = m.IssueRefreshToken("", 1)
	require.ErrorIs(t, err, auth.ErrEmptyUserID)
}
