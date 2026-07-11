package project

import (
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

func newProjectHandlerTest(t *testing.T, actorID string) (*gin.Engine, *workspaceRepoFake) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	svc, repo, _ := newWorkspaceServiceTest(t)
	enforcer, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	require.NoError(t, asmcasbin.SeedMVPolicies(enforcer))
	svc.enforcer = enforcer

	engine := gin.New()
	protected := engine.Group("/api/v1")
	protected.Use(func(c *gin.Context) {
		c.Set(auth.CtxUserID, actorID)
		c.Next()
	})
	NewHandler(svc, enforcer).RegisterRoutes(protected)
	return engine, repo
}

func TestWorkspaceSummaryHTTPContract(t *testing.T) {
	engine, repo := newProjectHandlerTest(t, "7")
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.memberSummary = WorkspaceSummary{
		Projects: WorkspaceProjectStats{Total: 1, Active: 1},
		Assets:   WorkspaceAssetStats{Total: 8},
		Risks:    WorkspaceRiskStats{Open: 3, CriticalHigh: 1},
		Tickets:  WorkspaceTicketStats{Open: 2},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/workspace/summary", nil)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	var body struct {
		Data WorkspaceSummary `json:"data"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	assert.Equal(t, int64(1), body.Data.Projects.Total)
	assert.Equal(t, int64(8), body.Data.Assets.Total)
	assert.Equal(t, "tenant-a", repo.memberTenant)
	assert.Equal(t, "7", repo.memberActor)
}

func TestProjectCapabilitiesHTTPContractAndTenantBoundary(t *testing.T) {
	engine, repo := newProjectHandlerTest(t, "7")
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.projects[1] = &Project{ID: 1, TenantID: "tenant-a", OrgID: "org-a", Status: StatusDraft}
	repo.projects[2] = &Project{ID: 2, TenantID: "tenant-b", OrgID: "org-b", Status: StatusActive}
	repo.members[1] = map[string]string{"7": asmcasbin.RoleProjectOwner}
	repo.members[2] = map[string]string{"7": asmcasbin.RoleProjectOwner}
	repo.onboarding = OnboardingCounts{OwnerCount: 1, PrimarySubjectCount: 1, PrimaryDomainCount: 1, ValidScopeCount: 1}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/capabilities", nil)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)

	var body struct {
		Data Capabilities `json:"data"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	assert.Equal(t, asmcasbin.RoleProjectOwner, body.Data.Role)
	assert.Contains(t, body.Data.Permissions, asmcasbin.PermProjectWrite)
	assert.True(t, body.Data.CanActivate)

	request = httptest.NewRequest(http.MethodGet, "/api/v1/projects/2/capabilities", nil)
	response = httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.NotContains(t, response.Body.String(), "tenant-b")
}
