package auth_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

// newAuthEngine wires the auth handler onto an httpx engine under /api/v1,
// mirroring production wiring with split public/protected route groups.
func newAuthEngine(t *testing.T, repo auth.UserRepository) *gin.Engine {
	t.Helper()
	mgr := testManager(t)
	svc := auth.NewService(repo, mgr, newEnforcer(t), audit.NewService(&capturingAuditRepo{}))
	engine := httpx.NewEngine(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	api := engine.Group("/api/v1")
	apiPublic := api.Group("")
	apiProtected := api.Group("")
	apiProtected.Use(auth.RequireAuth(mgr))
	auth.NewHandler(svc).RegisterRoutes(apiPublic, apiProtected)
	return engine
}

func postJSON(t *testing.T, engine *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)
	return w
}

func postJSONWithAuth(t *testing.T, engine *gin.Engine, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	engine.ServeHTTP(w, req)
	return w
}

func getWithAuth(t *testing.T, engine *gin.Engine, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	engine.ServeHTTP(w, req)
	return w
}

// decodeTokens extracts the token pair from a login/refresh success envelope.
func decodeTokens(t *testing.T, w *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var body struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body.Data.AccessToken, body.Data.RefreshToken
}

// Acceptance: POST /auth/login with valid credentials returns 200 + tokens.
func TestHandlerLoginSuccess(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass")).
		withMembership("1", 1, "project_owner"))

	w := postJSON(t, engine, "/api/v1/auth/login", map[string]string{
		"username": "admin", "password": "s3cret-pass",
	})
	require.Equal(t, http.StatusOK, w.Code)
	access, refresh := decodeTokens(t, w)
	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh)

	var body struct {
		Data struct {
			User struct {
				ID          string   `json:"id"`
				Name        string   `json:"name"`
				Role        string   `json:"role"`
				ProjectID   uint64   `json:"project_id"`
				Permissions []string `json:"permissions"`
			} `json:"user"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "1", body.Data.User.ID)
	assert.Equal(t, "admin", body.Data.User.Name)
	assert.Equal(t, "project_owner", body.Data.User.Role)
	assert.Equal(t, uint64(1), body.Data.User.ProjectID)
	assert.Contains(t, body.Data.User.Permissions, "asset:read")
}

func TestHandlerLoginReturnsPasswordChangeFlag(t *testing.T) {
	user := mustUser(t, 1, "admin", "Temporary-123")
	user.MustChangePassword = true
	engine := newAuthEngine(t, newFakeUserRepo(user))

	w := postJSON(t, engine, "/api/v1/auth/login", map[string]string{
		"username": "admin", "password": "Temporary-123",
	})
	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Data struct {
			User struct {
				MustChangePassword bool `json:"must_change_password"`
			} `json:"user"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.True(t, body.Data.User.MustChangePassword)
}

func TestHandlerChangePassword(t *testing.T) {
	repo := newFakeUserRepo(mustUser(t, 1, "admin", "Temporary-123"))
	engine := newAuthEngine(t, repo)
	login := postJSON(t, engine, "/api/v1/auth/login", map[string]string{
		"username": "admin", "password": "Temporary-123",
	})
	access, _ := decodeTokens(t, login)

	w := postJSONWithAuth(t, engine, "/api/v1/auth/password/change", map[string]string{
		"current_password": "wrong", "new_password": "Replacement-456",
	}, access)
	assertErrorEnvelope(t, w, http.StatusUnprocessableEntity, auth.ErrCodeCurrentPassword)

	w = postJSONWithAuth(t, engine, "/api/v1/auth/password/change", map[string]string{
		"current_password": "Temporary-123", "new_password": "Replacement-456",
	}, access)
	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, auth.CheckPassword(repo.byID[1].PasswordHash, "Replacement-456"))
}

// Acceptance: wrong password returns 401 with a uniform code and no detail.
func TestHandlerLoginWrongPassword(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass")))

	w := postJSON(t, engine, "/api/v1/auth/login", map[string]string{
		"username": "admin", "password": "nope",
	})
	assertErrorEnvelope(t, w, http.StatusUnauthorized, auth.ErrCodeInvalidCredentials)
}

// Acceptance: unknown user returns the identical 401 (no enumeration oracle).
func TestHandlerLoginUnknownUser(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass")))

	w := postJSON(t, engine, "/api/v1/auth/login", map[string]string{
		"username": "ghost", "password": "nope",
	})
	assertErrorEnvelope(t, w, http.StatusUnauthorized, auth.ErrCodeInvalidCredentials)
}

// A malformed body (missing fields) is a 400, distinct from an auth failure.
func TestHandlerLoginBadRequest(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo())
	w := postJSON(t, engine, "/api/v1/auth/login", map[string]string{"username": "admin"})
	assertErrorEnvelope(t, w, http.StatusBadRequest, httpx.ErrCodeBadRequest)
}

// Acceptance: refresh exchanges a refresh token for a new access token.
func TestHandlerRefreshSuccess(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass")))

	w := postJSON(t, engine, "/api/v1/auth/login", map[string]string{
		"username": "admin", "password": "s3cret-pass",
	})
	_, refresh := decodeTokens(t, w)

	w = postJSON(t, engine, "/api/v1/auth/refresh", map[string]string{"refresh_token": refresh})
	require.Equal(t, http.StatusOK, w.Code)
	access, newRefresh := decodeTokens(t, w)
	assert.NotEmpty(t, access)
	assert.NotEmpty(t, newRefresh)
}

// A garbage refresh token returns 401.
func TestHandlerRefreshInvalid(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo())
	w := postJSON(t, engine, "/api/v1/auth/refresh", map[string]string{"refresh_token": "not.a.token"})
	assertErrorEnvelope(t, w, http.StatusUnauthorized, auth.ErrCodeInvalidRefresh)
}

// Acceptance: an access token from login authorizes GET /auth/me.
func TestHandlerMeWithToken(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass")))

	w := postJSON(t, engine, "/api/v1/auth/login", map[string]string{
		"username": "admin", "password": "s3cret-pass",
	})
	access, _ := decodeTokens(t, w)

	w = getWithAuth(t, engine, "/api/v1/auth/me", access)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Data struct {
			ID          string `json:"id"`
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			TenantID    string `json:"tenant_id"`
			OrgID       string `json:"org_id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "1", body.Data.ID)
	assert.Equal(t, "admin", body.Data.Username)
	assert.Equal(t, "t1", body.Data.TenantID)
	assert.Equal(t, "o1", body.Data.OrgID)
}

// Acceptance: GET /auth/me without a token returns 401.
func TestHandlerMeNoToken(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass")))
	w := getWithAuth(t, engine, "/api/v1/auth/me", "")
	assertErrorEnvelope(t, w, http.StatusUnauthorized, httpx.ErrCodeUnauthorized)
}

// GET /auth/permissions requires a token and returns the permission list.
func TestHandlerPermissions(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass")))

	w := postJSON(t, engine, "/api/v1/auth/login", map[string]string{
		"username": "admin", "password": "s3cret-pass",
	})
	access, _ := decodeTokens(t, w)

	w = getWithAuth(t, engine, "/api/v1/auth/permissions", access)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Data struct {
			Permissions []string `json:"permissions"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.NotNil(t, body.Data.Permissions)
}

// The me response body must never expose the password hash.
func TestHandlerMeOmitsPasswordHash(t *testing.T) {
	engine := newAuthEngine(t, newFakeUserRepo(mustUser(t, 1, "admin", "s3cret-pass")))

	w := postJSON(t, engine, "/api/v1/auth/login", map[string]string{
		"username": "admin", "password": "s3cret-pass",
	})
	access, _ := decodeTokens(t, w)

	w = getWithAuth(t, engine, "/api/v1/auth/me", access)
	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "password_hash")
	assert.NotContains(t, w.Body.String(), "$2a$")
}
