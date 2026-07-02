package auth_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// newEnforcer builds an in-memory Casbin enforcer with a policy that exercises
// both project-scoped and global roles.
func newEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)

	policies := [][]string{
		{asmcasbin.RoleProjectOwner, "p1", asmcasbin.PermAssetRead, "allow"},
		{asmcasbin.RoleSystemAdmin, asmcasbin.GlobalDomain, asmcasbin.PermAssetRead, "allow"},
	}
	for _, p := range policies {
		ok, err := e.AddPolicy(p[0], p[1], p[2], p[3])
		require.NoError(t, err)
		require.True(t, ok)
	}

	assignments := [][]string{
		{"alice", asmcasbin.RoleProjectOwner, "p1"},                // alice owns p1 only
		{"bob", asmcasbin.RoleSystemAdmin, asmcasbin.GlobalDomain}, // bob is global admin
	}
	for _, g := range assignments {
		ok, err := e.AddGroupingPolicy(g[0], g[1], g[2])
		require.NoError(t, err)
		require.True(t, ok)
	}
	return e
}

// newEngine wires a public /healthz and a protected asset route that requires
// asset:read, mirroring how a real handler chain composes the middleware.
func newEngine(t *testing.T, m *auth.JWTManager, e *casbin.Enforcer) *gin.Engine {
	t.Helper()
	engine := httpx.NewEngine(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	engine.GET("/api/v1/projects/:project_id/assets",
		auth.RequireAuth(m),
		auth.ProjectIDFromParam("project_id"),
		auth.RequirePermission(e, asmcasbin.PermAssetRead),
		func(c *gin.Context) {
			httpx.OK(c, gin.H{
				"user_id":    c.GetString(auth.CtxUserID),
				"project_id": c.GetString(auth.CtxProjectID),
			})
		},
	)
	return engine
}

func doRequest(t *testing.T, engine *gin.Engine, target, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	engine.ServeHTTP(w, req)
	return w
}

func assertErrorEnvelope(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	require.Equal(t, wantStatus, w.Code)
	var body httpx.ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, wantCode, body.Error.Code)
	assert.NotEmpty(t, body.RequestID, "error response must carry request_id")
}

// Acceptance: /healthz stays open without a token.
func TestHealthzRequiresNoAuth(t *testing.T) {
	engine := newEngine(t, testManager(t), newEnforcer(t))
	w := doRequest(t, engine, "/healthz", "")
	assert.Equal(t, http.StatusOK, w.Code)
}

// Acceptance: protected route with no token -> 401.
func TestProtectedNoToken(t *testing.T) {
	engine := newEngine(t, testManager(t), newEnforcer(t))
	w := doRequest(t, engine, "/api/v1/projects/p1/assets", "")
	assertErrorEnvelope(t, w, http.StatusUnauthorized, httpx.ErrCodeUnauthorized)
}

// Acceptance: malformed Bearer header -> 401.
func TestProtectedMalformedBearer(t *testing.T) {
	engine := newEngine(t, testManager(t), newEnforcer(t))
	cases := map[string]string{
		"wrong_scheme": "Token xyz",
		"bare_bearer":  "Bearer",
		"lowercase":    "bearer xyz",
		"empty_token":  "Bearer ",
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			w := doRequest(t, engine, "/api/v1/projects/p1/assets", hdr)
			assertErrorEnvelope(t, w, http.StatusUnauthorized, httpx.ErrCodeUnauthorized)
		})
	}
}

// Acceptance: garbage token -> 401.
func TestProtectedInvalidToken(t *testing.T) {
	engine := newEngine(t, testManager(t), newEnforcer(t))
	w := doRequest(t, engine, "/api/v1/projects/p1/assets", "Bearer not.a.real.token")
	assertErrorEnvelope(t, w, http.StatusUnauthorized, httpx.ErrCodeUnauthorized)
}

// Acceptance: expired token -> 401.
func TestProtectedExpiredToken(t *testing.T) {
	expiring, err := auth.NewManager(auth.Config{
		AccessSecret:  testAccessSecret,
		RefreshSecret: testRefreshSecret,
		AccessTTL:     -1 * time.Second,
	})
	require.NoError(t, err)
	tok, err := expiring.IssueAccessToken("alice")
	require.NoError(t, err)

	// Engine uses a manager with the same access secret, so the signature is
	// valid and only the expiry causes rejection.
	engine := newEngine(t, testManager(t), newEnforcer(t))
	w := doRequest(t, engine, "/api/v1/projects/p1/assets", "Bearer "+tok)
	assertErrorEnvelope(t, w, http.StatusUnauthorized, httpx.ErrCodeUnauthorized)
}

// Acceptance: valid token but insufficient permission -> 403.
func TestProtectedValidButNoPermission(t *testing.T) {
	m := testManager(t)
	engine := newEngine(t, m, newEnforcer(t))
	tok, err := m.IssueAccessToken("carol") // carol has no role at all
	require.NoError(t, err)

	w := doRequest(t, engine, "/api/v1/projects/p1/assets", "Bearer "+tok)
	assertErrorEnvelope(t, w, http.StatusForbidden, httpx.ErrCodeForbidden)
}

// Acceptance: valid token with permission -> 200, response carries request_id.
func TestProtectedValidWithPermission(t *testing.T) {
	m := testManager(t)
	engine := newEngine(t, m, newEnforcer(t))
	tok, err := m.IssueAccessToken("alice") // alice has asset:read in p1
	require.NoError(t, err)

	w := doRequest(t, engine, "/api/v1/projects/p1/assets", "Bearer "+tok)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		RequestID string `json:"request_id"`
		Data      struct {
			UserID    string `json:"user_id"`
			ProjectID string `json:"project_id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "alice", body.Data.UserID)
	assert.Equal(t, "p1", body.Data.ProjectID)
	assert.NotEmpty(t, body.RequestID, "success response must carry request_id")
}

// Acceptance: Casbin project isolation holds through the middleware — alice can
// read her own project but is denied in another.
func TestProjectIsolationThroughMiddleware(t *testing.T) {
	m := testManager(t)
	engine := newEngine(t, m, newEnforcer(t))
	tok, err := m.IssueAccessToken("alice") // asset:read in p1 ONLY
	require.NoError(t, err)

	w := doRequest(t, engine, "/api/v1/projects/p1/assets", "Bearer "+tok)
	require.Equal(t, http.StatusOK, w.Code, "alice should access her own project")

	w = doRequest(t, engine, "/api/v1/projects/p2/assets", "Bearer "+tok)
	assertErrorEnvelope(t, w, http.StatusForbidden, httpx.ErrCodeForbidden)
}

// Sanity: a global role crosses projects through the same middleware path.
func TestGlobalRoleCrossesProjects(t *testing.T) {
	m := testManager(t)
	engine := newEngine(t, m, newEnforcer(t))
	tok, err := m.IssueAccessToken("bob") // global system_admin
	require.NoError(t, err)

	w := doRequest(t, engine, "/api/v1/projects/p2/assets", "Bearer "+tok)
	require.Equal(t, http.StatusOK, w.Code, "global admin should access any project")
}

// RequireAuth must reject a token whose user id is empty even if its signature
// is otherwise valid. The manager refuses to issue one, so forge it directly
// with the jwt library and the known access secret.
func TestProtectedTokenWithEmptyUserIDRejected(t *testing.T) {
	m := testManager(t)
	now := time.Now()
	forge := struct {
		UserID string `json:"uid"`
		jwt.RegisteredClaims
	}{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, forge).SignedString([]byte(testAccessSecret))
	require.NoError(t, err)

	engine := newEngine(t, m, newEnforcer(t))
	w := doRequest(t, engine, "/api/v1/projects/p1/assets", "Bearer "+tok)
	assertErrorEnvelope(t, w, http.StatusUnauthorized, httpx.ErrCodeUnauthorized)
}
