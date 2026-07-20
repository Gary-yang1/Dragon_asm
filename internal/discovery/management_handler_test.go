package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

type fakeDiscoveryProjectAccess struct {
	project *project.Project
	role    string
	err     error
	seenID  uint64
}

type fakeTaskRunEnqueuer struct {
	payloads []DispatchTaskPayload
	err      error
}

func (f *fakeTaskRunEnqueuer) EnqueueTaskRun(_ context.Context, payload DispatchTaskPayload) error {
	f.payloads = append(f.payloads, payload)
	return f.err
}

func (f *fakeDiscoveryProjectAccess) Access(_ context.Context, _ string, projectID uint64) (*project.Project, string, error) {
	f.seenID = projectID
	if f.err != nil {
		return nil, "", f.err
	}
	return f.project, f.role, nil
}

func TestManagementHandlerScopePermissionAndProjectMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return now }))
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{
		ID: 7, TenantID: "tenant-a", OrgID: "org-a", Status: project.StatusActive,
	}, role: asmcasbin.RoleProjectOwner}
	router := managementRouter(t, svc, projects)

	body := []byte(`{
		"name":"production domains",
		"status":"active",
		"authorized_by":"owner-1",
		"valid_from":"` + now.Format(time.RFC3339) + `",
		"valid_until":"` + now.Add(time.Hour).Format(time.RFC3339) + `",
		"targets":[{"target_type":"domain","match_mode":"include","value":"example.com"}]
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/7/scopes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, uint64(7), projects.seenID)

	created, err := svc.GetScope(context.Background(), 7, 1)
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", created.TenantID)
	assert.Equal(t, "org-a", created.OrgID)
	assert.Equal(t, "example.com", created.Targets[0].Value)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/projects/7/scopes", nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"targets":[{"id":1,"target_type":"domain","match_mode":"include","value":"example.com"}]`)
}

func TestManagementHandlerSecurityOpsCanReadButCannotWriteScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := NewService(newFakeRepo())
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{ID: 2, TenantID: "t", Status: project.StatusActive}, role: asmcasbin.RoleSecurityOps}
	router := managementRouter(t, svc, projects)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/projects/2/scopes", nil))
	assert.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/2/scopes", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestManagementHandlerRejectsCrossProjectAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	projects := &fakeDiscoveryProjectAccess{err: project.ErrForbidden}
	router := managementRouter(t, NewService(newFakeRepo()), projects)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/projects/99/discovery/runs", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, uint64(99), projects.seenID)
}

func TestManagementHandlerInactiveProjectCannotCreateRun(t *testing.T) {
	gin.SetMode(gin.TestMode)
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{
		ID: 3, TenantID: "t", OrgID: "o", Status: project.StatusSuspended,
	}, role: asmcasbin.RoleProjectOwner}
	router := managementRouter(t, NewService(newFakeRepo()), projects)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/projects/3/discovery/templates/1/runs", nil))
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), errCodeProjectNotActive)
}

func TestManagementHandlerCreatesPendingRunAndPaginates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC()
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return now }))
	scope, err := svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID: "t", OrgID: "o", ProjectID: 4, Name: "scope", Status: StatusActive,
		AuthorizedBy: "owner", ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour), ActorID: "1",
		Targets: []ScopeTargetInput{{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com"}},
	})
	require.NoError(t, err)
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{
		ID: 4, TenantID: "t", OrgID: "o", Status: project.StatusActive,
	}, role: asmcasbin.RoleProjectOwner}
	router := managementRouter(t, svc, projects)

	templateBody := []byte(`{
		"scope_id":` + uintString(scope.ID) + `,
		"name":"passive",
		"task_type":"passive_intel",
		"config":{"targets":[{"type":"domain","value":"example.com"}],"options":{}},
		"enabled":true,
		"timeout_seconds":60,
		"rate_limit":10,
		"concurrency":2,
		"retry_limit":1
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/4/discovery/templates", bytes.NewReader(templateBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var templateEnvelope struct {
		Data templateResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &templateEnvelope))
	require.NotZero(t, templateEnvelope.Data.ID)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/projects/4/discovery/templates/"+uintString(templateEnvelope.Data.ID)+"/runs", nil))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"status":"pending"`)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/projects/4/discovery/runs?page_number=1&page_size=1&sort_by=id&sort_order=desc", nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var envelope struct {
		Data struct {
			Items []runResponse `json:"items"`
			Total int64         `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	assert.Equal(t, int64(1), envelope.Data.Total)
	assert.Len(t, envelope.Data.Items, 1)
}

func TestManagementHandlerRejectsUnknownSortField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{ID: 5, TenantID: "t", Status: project.StatusActive}, role: asmcasbin.RoleViewer}
	router := managementRouter(t, NewService(newFakeRepo()), projects)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/projects/5/discovery/runs?sort_by=drop_table", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func managementRouter(t *testing.T, svc *Service, projects discoveryProjectAccess) *gin.Engine {
	t.Helper()
	if svc.dispatchEnqueuer == nil {
		svc.dispatchEnqueuer = &fakeTaskRunEnqueuer{}
	}
	enforcer, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	require.NoError(t, asmcasbin.SeedMVPolicies(enforcer))
	return managementRouterWithEnforcer(svc, projects, enforcer)
}

func managementRouterWithEnforcer(svc *Service, projects discoveryProjectAccess, enforcer *casbin.Enforcer) *gin.Engine {
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		c.Set(auth.CtxUserID, "1")
		c.Next()
	})
	NewManagementHandler(svc, projects, enforcer).RegisterRoutes(api)
	return router
}

func uintString(value uint64) string {
	return strconv.FormatUint(value, 10)
}
