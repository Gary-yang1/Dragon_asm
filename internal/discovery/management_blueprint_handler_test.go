package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

func TestManagementHandlerListsAndPreviewsBlueprintsWithReadPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(
		repo,
		WithNow(func() time.Time { return now }),
		WithEngineRouter(NewTaskTypeEngineRouter(&fakeEngine{}, nil)),
	)
	scope, err := svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID: "t", OrgID: "o", ProjectID: 12, Name: "domains", Status: StatusActive,
		AuthorizedBy: "owner", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), ActorID: "1",
		Targets: []ScopeTargetInput{{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com"}},
	})
	require.NoError(t, err)
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{
		ID: 12, TenantID: "t", OrgID: "o", Status: project.StatusActive,
	}, role: asmcasbin.RoleViewer}
	router := managementRouter(t, svc, projects)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/projects/12/discovery/blueprints?page_size=100", nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listEnvelope struct {
		Data struct {
			Items []DiscoveryBlueprint `json:"items"`
			Total int64                `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listEnvelope))
	assert.Len(t, listEnvelope.Data.Items, 5)
	assert.Equal(t, int64(5), listEnvelope.Data.Total)

	body := []byte(`{}`)
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/12/discovery/blueprints/domain_asset_inventory/preview",
		bytes.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"execution_mode":"preview_only"`)
	assert.Contains(t, w.Body.String(), `"scope_selection":"only_compatible"`)
	assert.Contains(t, w.Body.String(), `"id":`+uintString(scope.ID))
	assert.Contains(t, w.Body.String(), `"ready":true`)
	assert.Contains(t, w.Body.String(), `"issues":[]`)
	assert.Contains(t, w.Body.String(), `"depends_on":[]`)
}

func TestManagementHandlerBlueprintPreviewReportsAmbiguousAutomaticScopeSelection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return now }))
	for _, name := range []string{"first", "second"} {
		_, err := svc.CreateScope(context.Background(), CreateScopeInput{
			TenantID: "t", OrgID: "o", ProjectID: 14, Name: name, Status: StatusActive,
			AuthorizedBy: "owner", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), ActorID: "1",
			Targets: []ScopeTargetInput{{
				TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: name + ".example.com",
			}},
		})
		require.NoError(t, err)
	}
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{
		ID: 14, TenantID: "t", OrgID: "o", Status: project.StatusActive,
	}, role: asmcasbin.RoleViewer}
	router := managementRouter(t, svc, projects)

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/14/discovery/blueprints/domain_asset_inventory/preview",
		bytes.NewReader([]byte(`{}`)),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "DISCOVERY_BLUEPRINT_SCOPE_REQUIRED")
}

func TestManagementHandlerBlueprintPreviewUsesProjectIsolationAndStableErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	projects := &fakeDiscoveryProjectAccess{err: project.ErrForbidden}
	router := managementRouter(t, NewService(newFakeRepo()), projects)
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/99/discovery/blueprints/domain_asset_inventory/preview",
		bytes.NewReader([]byte(`{"scope_id":1}`)),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	projects = &fakeDiscoveryProjectAccess{project: &project.Project{
		ID: 13, TenantID: "t", Status: project.StatusActive,
	}, role: asmcasbin.RoleViewer}
	router = managementRouter(t, NewService(newFakeRepo()), projects)
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/13/discovery/blueprints/not_found/preview",
		bytes.NewReader([]byte(`{"scope_id":1}`)),
	)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "DISCOVERY_BLUEPRINT_NOT_FOUND")
}

func TestManagementHandlerMaterializesBlueprintTemplatesWithoutRuns(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	engine := &fakeEngine{}
	svc := NewService(
		repo,
		WithNow(func() time.Time { return now }),
		WithEngineRouter(NewTaskTypeEngineRouter(engine, nil)),
	)
	scope, err := svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID: "t", OrgID: "o", ProjectID: 17, Name: "domains", Status: StatusActive,
		AuthorizedBy: "owner", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), ActorID: "1",
		Targets: []ScopeTargetInput{{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com"}},
	})
	require.NoError(t, err)
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{
		ID: 17, TenantID: "t", OrgID: "o", Status: project.StatusActive,
	}, role: asmcasbin.RoleProjectOwner}
	router := managementRouter(t, svc, projects)

	call := func() blueprintTemplatesResponse {
		t.Helper()
		requestBody := []byte(`{"scope_id":` + uintString(scope.ID) + `}`)
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/projects/17/discovery/blueprints/domain_asset_inventory/templates",
			bytes.NewReader(requestBody),
		)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var envelope struct {
			Data blueprintTemplatesResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
		return envelope.Data
	}

	first := call()
	assert.Equal(t, 2, first.CreatedCount)
	assert.Zero(t, first.ExistingCount)
	assert.Equal(t, 2, first.TargetCount)
	require.Len(t, first.Templates, 2)
	for _, item := range first.Templates {
		assert.Equal(t, 1, item.BatchIndex)
		assert.Equal(t, 1, item.BatchCount)
		assert.Equal(t, 1, item.TargetCount)
	}
	assert.Len(t, repo.templates[17], 2)
	assert.Empty(t, repo.runs[17])
	assert.Zero(t, engine.dispatchCalls)

	second := call()
	assert.Zero(t, second.CreatedCount)
	assert.Equal(t, 2, second.ExistingCount)
	assert.Len(t, repo.templates[17], 2)
	assert.Empty(t, repo.runs[17])
	assert.Zero(t, engine.dispatchCalls)
}
