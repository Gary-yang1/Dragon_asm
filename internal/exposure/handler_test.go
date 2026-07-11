package exposure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

type fakeProjectAccess struct {
	role string
	err  error
}

func (f fakeProjectAccess) Access(_ context.Context, _ string, projectID uint64) (*project.Project, string, error) {
	if f.err != nil {
		return nil, "", f.err
	}
	return &project.Project{ID: projectID, Status: project.StatusActive}, f.role, nil
}

func TestHandlerListExposures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.Ingest(context.Background(), IngestInput{TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 2, ExposureType: TypePort, Protocol: "tcp", Port: 443})
	require.NoError(t, err)
	router := exposureRouter(t, svc, fakeProjectAccess{role: asmcasbin.RoleViewer})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/projects/1/exposures", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"total":1`)
	assert.Contains(t, w.Body.String(), `"exposure_type":"port"`)
}

func TestHandlerDetailIsProjectScoped(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newFakeRepo()
	svc := NewService(repo)
	res, err := svc.Ingest(context.Background(), IngestInput{TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 2, ExposureType: TypePort, Protocol: "tcp", Port: 443})
	require.NoError(t, err)
	router := exposureRouter(t, svc, fakeProjectAccess{role: asmcasbin.RoleViewer})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/projects/2/exposures/1", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/projects/1/exposures/1", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), res.Exposure.ExposureKey)
}

func exposureRouter(t *testing.T, svc *Service, projects projectAccess) *gin.Engine {
	t.Helper()
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	require.NoError(t, asmcasbin.SeedMVPolicies(e))
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(auth.CtxUserID, "alice")
		c.Next()
	})
	NewHandler(svc, projects, e).RegisterRoutes(router.Group(""))
	return router
}

func TestHandlerPermissionDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(auth.CtxUserID, "alice")
		c.Next()
	})
	NewHandler(NewService(newFakeRepo()), fakeProjectAccess{role: asmcasbin.RoleViewer}, e).RegisterRoutes(router.Group(""))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/projects/1/exposures", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestToResponseIncludesCPE(t *testing.T) {
	now := time.Now().UTC()
	resp := toResponse(&Exposure{
		ID: 1, ProjectID: 1, AssetID: 2, ExposureType: TypeService, CPE: "cpe:2.3:a:*:nginx:1.0:*:*:*:*:*:*:*",
		FirstSeen: now, LastSeen: now, CreatedAt: now, UpdatedAt: now,
	})
	assert.Equal(t, "cpe:2.3:a:*:nginx:1.0:*:*:*:*:*:*:*", resp.CPE)
}
