package auth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

func adminHandlerEngine(service *auth.AdminUserService, actorID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	protected := engine.Group("/api/v1")
	protected.Use(func(c *gin.Context) {
		c.Set(auth.CtxUserID, actorID)
		c.Next()
	})
	auth.NewAdminUserHandler(service).RegisterRoutes(protected)
	return engine
}

func adminRequest(t *testing.T, engine *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	return response
}

func decodeAdminResponse(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	return body
}

func TestAdminUserHandlerCrossTenantDetailReturns404(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(2, "tenant-2", ""))
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)
	response := adminRequest(t, adminHandlerEngine(service, "1"), http.MethodGet, "/api/v1/admin/users/2", "")

	assert.Equal(t, http.StatusNotFound, response.Code)
	body := decodeAdminResponse(t, response)
	errorBody := body["error"].(map[string]any)
	assert.Equal(t, auth.ErrCodePlatformUserNotFound, errorBody["code"])
}

func TestAdminUserHandlerSecurityAdminGets403(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(2, "tenant-1", ""))
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSecurityAdmin)
	response := adminRequest(t, adminHandlerEngine(service, "1"), http.MethodGet, "/api/v1/admin/users", "")

	assert.Equal(t, http.StatusForbidden, response.Code)
}

func TestAdminUserHandlerPasswordResetRequiresTemporaryPassword(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(2, "tenant-1", ""))
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)
	response := adminRequest(t, adminHandlerEngine(service, "1"), http.MethodPost, "/api/v1/admin/users/2/password-reset", `{}`)

	assert.Equal(t, http.StatusBadRequest, response.Code)
}

func TestAdminUserHandlerPasswordResetDoesNotEchoSecretOrVersion(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(2, "tenant-1", ""))
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)
	response := adminRequest(t, adminHandlerEngine(service, "1"), http.MethodPost, "/api/v1/admin/users/2/password-reset", `{"temporary_password":"Replacement-123"}`)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.NotContains(t, response.Body.String(), "Replacement-123")
	assert.NotContains(t, response.Body.String(), "auth_version")
	assert.NotContains(t, response.Body.String(), "password_hash")
}

func TestAdminUserHandlerCanClearTenantRoleWithNull(t *testing.T) {
	repo := newAdminUserRepoFake(
		activePlatformUser(1, "tenant-1", auth.PlatformRoleSystemAdmin),
		activePlatformUser(2, "tenant-1", auth.PlatformRoleSecurityAdmin),
	)
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)
	response := adminRequest(t, adminHandlerEngine(service, "1"), http.MethodPut, "/api/v1/admin/users/2/tenant-role", `{"role":null}`)

	assert.Equal(t, http.StatusOK, response.Code)
	body := decodeAdminResponse(t, response)
	data := body["data"].(map[string]any)
	assert.Nil(t, data["role"])
	assert.Equal(t, uint32(2), repo.authVersion[2])
}

func TestAdminUserHandlerListIsTenantScoped(t *testing.T) {
	repo := newAdminUserRepoFake(
		activePlatformUser(2, "tenant-1", ""),
		activePlatformUser(3, "tenant-2", ""),
	)
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)
	response := adminRequest(t, adminHandlerEngine(service, "1"), http.MethodGet, "/api/v1/admin/users?page_size=100", "")

	assert.Equal(t, http.StatusOK, response.Code)
	body := decodeAdminResponse(t, response)
	data := body["data"].(map[string]any)
	items := data["items"].([]any)
	require.Len(t, items, 1)
	assert.Equal(t, float64(2), items[0].(map[string]any)["id"])
	assert.NotContains(t, response.Body.String(), "tenant-2")
}
