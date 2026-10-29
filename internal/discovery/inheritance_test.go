package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

func (r *fakeRepo) ListInheritanceObservations(_ context.Context, projectID, runID, afterID uint64, limit int32) ([]*DiscoveryObservation, error) {
	result := []*DiscoveryObservation{}
	for _, item := range r.observations[projectID] {
		if item.RunID == runID && item.ID > afterID && item.Kind == ObservationKindAsset && item.IngestStatus == ObservationStatusMaterialized {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if len(result) > int(limit) {
		result = result[:limit]
	}
	return result, nil
}
func inheritanceFixture(t *testing.T) (*Service, *fakeRepo) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return now }))
	scope, err := svc.CreateScope(context.Background(), CreateScopeInput{TenantID: "tenant", OrgID: "org", ProjectID: 1, Name: "Parent", Status: StatusActive, AuthorizedBy: "owner", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour), ActorID: "1", Targets: []ScopeTargetInput{
		{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, CoverageMode: CoverageModeSubdomains, Value: "example.com"},
		{TargetType: TargetTypeDomain, MatchMode: MatchModeExclude, CoverageMode: CoverageModeSubdomains, Value: "excluded.example.com"},
		{TargetType: TargetTypeCIDR, MatchMode: MatchModeInclude, Value: "8.8.8.0/24"},
	}})
	require.NoError(t, err)
	repo.runs[1] = map[uint64]*TaskRun{10: {ID: 10, ProjectID: 1, TenantID: "tenant", OrgID: "org", ScopeID: scope.ID, TaskType: TaskTypePassiveIntel, Status: TaskRunStatusSuccess}}
	repo.observations[1] = map[uint64]*DiscoveryObservation{}
	cases := []struct{ kind, value string }{{"subdomain", "api.example.com"}, {"subdomain", "excluded.example.com"}, {"domain", "notexample.com"}, {"ip", "8.8.8.8"}, {"ip", "1.1.1.1"}, {"ip", "127.0.0.1"}, {"web", "https://api.example.com"}}
	for i, item := range cases {
		raw, err := json.Marshal(callbackAssetV1{AssetType: item.kind, Value: item.value})
		require.NoError(t, err)
		id := uint64(i + 1)
		repo.observations[1][id] = &DiscoveryObservation{ID: id, ProjectID: 1, TenantID: "tenant", OrgID: "org", RunID: 10, Seq: 1, Kind: ObservationKindAsset, Provider: "test", ObservedAt: now, NormalizedJSON: raw, IngestStatus: ObservationStatusMaterialized}
	}
	return svc, repo
}
func TestInheritanceClassification(t *testing.T) {
	svc, repo := inheritanceFixture(t)
	page, err := svc.ListDerivedTargets(context.Background(), 1, 10, 0)
	require.NoError(t, err)
	require.Len(t, page.Items, 7)
	assert.True(t, page.ParentActive)
	assert.True(t, page.SourceComplete)
	assert.Equal(t, []string{"inherited", "excluded", "pending", "inherited", "pending", "excluded", "inherited"}, []string{page.Items[0].Status, page.Items[1].Status, page.Items[2].Status, page.Items[3].Status, page.Items[4].Status, page.Items[5].Status, page.Items[6].Status})
	repo.targets[1][1][0].CoverageMode = CoverageModeExact
	page, err = svc.ListDerivedTargets(context.Background(), 1, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, "pending", page.Items[0].Status)
	repo.scopes[1][1].Status = StatusInactive
	page, err = svc.ListDerivedTargets(context.Background(), 1, 10, 0)
	require.NoError(t, err)
	assert.False(t, page.ParentActive)
	assert.Equal(t, "blocked", page.Items[0].Status)
}
func TestInheritanceSnapshotsAndRevocation(t *testing.T) {
	ctx := context.Background()
	svc, repo := inheritanceFixture(t)
	page, err := svc.ListDerivedTargets(ctx, 1, 10, 0)
	require.NoError(t, err)
	in := CreateContinuationInput{ProjectID: 1, SourceRunID: 10, TaskType: TaskTypeDNS, ObservationIDs: []uint64{1}, ScopeFingerprint: page.ScopeFingerprint, ActorID: "1"}
	template, err := svc.CreateContinuationTemplate(ctx, in)
	require.NoError(t, err)
	reused, err := svc.CreateContinuationTemplate(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, template.ID, reused.ID)
	assert.Len(t, repo.templates[1], 1)
	assert.Equal(t, uint64(1), template.ScopeID)
	assert.Contains(t, template.Config, `"source_run_id":10`)
	run, err := svc.CreateTaskRun(ctx, CreateTaskRunInput{ProjectID: 1, TemplateID: template.ID, ActorID: "1"})
	require.NoError(t, err)
	plan, err := svc.BuildDispatchPlan(ctx, 1, run.ID, "1")
	require.NoError(t, err)
	require.Len(t, plan.Targets, 1)
	assert.Equal(t, "api.example.com", plan.Targets[0].Value)
	config := "{}"
	_, err = svc.UpdateTaskTemplate(ctx, UpdateTaskTemplateInput{ProjectID: 1, TemplateID: template.ID, ActorID: "1", Config: &config})
	require.ErrorIs(t, err, ErrInheritanceImmutable)
	repo.scopes[1][1].Status = StatusInactive
	_, err = svc.BuildDispatchPlan(ctx, 1, run.ID, "1")
	require.ErrorIs(t, err, ErrInheritanceNotReady)
	_, err = svc.CreateTaskRun(ctx, CreateTaskRunInput{ProjectID: 1, TemplateID: template.ID, ActorID: "1"})
	require.ErrorIs(t, err, ErrInheritanceNotReady)
}
func TestInheritanceRejectsChangedEvidenceAndForgedInputs(t *testing.T) {
	ctx := context.Background()
	svc, repo := inheritanceFixture(t)
	page, _ := svc.ListDerivedTargets(ctx, 1, 10, 0)
	template, err := svc.CreateContinuationTemplate(ctx, CreateContinuationInput{ProjectID: 1, SourceRunID: 10, TaskType: TaskTypeDNS, ObservationIDs: []uint64{1}, ScopeFingerprint: page.ScopeFingerprint, ActorID: "1"})
	require.NoError(t, err)
	repo.observations[1][1].NormalizedJSON = []byte(`{"asset_type":"subdomain","value":"changed.example.com"}`)
	err = svc.validateInheritedSnapshot(ctx, 1, 1, TaskTypeDNS, template.Config)
	require.ErrorIs(t, err, ErrInheritanceNotReady)
	_, err = svc.CreateContinuationTemplate(ctx, CreateContinuationInput{ProjectID: 1, SourceRunID: 10, TaskType: TaskTypeDNS, ObservationIDs: []uint64{3}, ScopeFingerprint: page.ScopeFingerprint, ActorID: "1"})
	require.ErrorIs(t, err, ErrInheritanceNotReady)
	repo.observations[1][1].RunID = 999
	_, err = svc.CreateContinuationTemplate(ctx, CreateContinuationInput{ProjectID: 1, SourceRunID: 10, TaskType: TaskTypeDNS, ObservationIDs: []uint64{1}, ScopeFingerprint: page.ScopeFingerprint, ActorID: "1"})
	require.ErrorIs(t, err, ErrInheritanceInvalid)
	_, err = svc.ListDerivedTargets(ctx, 2, 10, 0)
	require.Error(t, err)
}
func TestInheritanceExplicitAuthorizationPreservesBoundary(t *testing.T) {
	ctx := context.Background()
	svc, repo := inheritanceFixture(t)
	page, _ := svc.ListDerivedTargets(ctx, 1, 10, 0)
	before, _ := svc.GetScope(ctx, 1, 1)
	updated, err := svc.AuthorizeDerivedTargets(ctx, AuthorizeDerivedInput{ProjectID: 1, SourceRunID: 10, ObservationIDs: []uint64{5}, ScopeFingerprint: page.ScopeFingerprint, Reason: "Approved owned address", ActorID: "1"})
	require.NoError(t, err)
	assert.Equal(t, before.ValidUntil, updated.ValidUntil)
	assert.Equal(t, before.Status, updated.Status)
	assert.Len(t, updated.Targets, 4)
	page2, _ := svc.ListDerivedTargets(ctx, 1, 10, 0)
	assert.Equal(t, "inherited", page2.Items[4].Status)
	_, err = svc.AuthorizeDerivedTargets(ctx, AuthorizeDerivedInput{ProjectID: 1, SourceRunID: 10, ObservationIDs: []uint64{3}, ScopeFingerprint: page.ScopeFingerprint, Reason: "stale", ActorID: "1"})
	require.ErrorIs(t, err, ErrInheritanceScopeChanged)
	for _, id := range []uint64{2, 6} {
		_, err = svc.AuthorizeDerivedTargets(ctx, AuthorizeDerivedInput{ProjectID: 1, SourceRunID: 10, ObservationIDs: []uint64{id}, ScopeFingerprint: page2.ScopeFingerprint, Reason: "cannot bypass exclude", ActorID: "1"})
		require.ErrorIs(t, err, ErrInheritanceNotReady)
	}
	assert.Len(t, repo.targets[1][1], 4)
}
func TestInheritanceDoesNotBypassActiveOwnership(t *testing.T) {
	ctx := context.Background()
	svc, _ := inheritanceFixture(t)
	svc.activePolicy = ActiveDispatchPolicy{Enabled: true, RequireOwnership: true}
	page, _ := svc.ListDerivedTargets(ctx, 1, 10, 0)
	template, err := svc.CreateContinuationTemplate(ctx, CreateContinuationInput{ProjectID: 1, SourceRunID: 10, TaskType: TaskTypePortProbe, ObservationIDs: []uint64{4}, ScopeFingerprint: page.ScopeFingerprint, ActorID: "1"})
	require.NoError(t, err)
	run, err := svc.CreateTaskRun(ctx, CreateTaskRunInput{ProjectID: 1, TemplateID: template.ID, ActorID: "1"})
	require.NoError(t, err)
	_, err = svc.BuildDispatchPlan(ctx, 1, run.ID, "1")
	require.ErrorIs(t, err, ErrOwnershipRequired)
}
func TestInheritanceHandlerScopeExpansionNeedsScopeWrite(t *testing.T) {
	svc, _ := inheritanceFixture(t)
	page, _ := svc.ListDerivedTargets(context.Background(), 1, 10, 0)
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{ID: 1, TenantID: "tenant", OrgID: "org", Status: project.StatusActive}, role: asmcasbin.RoleSecurityOps}
	router := managementRouter(t, svc, projects)
	raw, _ := json.Marshal(derivedSelectionRequest{ObservationIDs: []uint64{5}, ScopeFingerprint: page.ScopeFingerprint, Reason: "authorized"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/discovery/runs/10/derived-targets/authorize", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/discovery/runs/10/derived-targets", nil))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
}

func TestInheritanceReusesRenamedSnapshotAndHonorsDisabledTemplate(t *testing.T) {
	ctx := context.Background()
	svc, repo := inheritanceFixture(t)
	page, _ := svc.ListDerivedTargets(ctx, 1, 10, 0)
	input := CreateContinuationInput{ProjectID: 1, SourceRunID: 10, TaskType: TaskTypeDNS, ObservationIDs: []uint64{1}, ScopeFingerprint: page.ScopeFingerprint, ActorID: "1"}
	template, err := svc.CreateContinuationTemplate(ctx, input)
	require.NoError(t, err)
	repo.templates[1][template.ID].Name = "Renamed configuration"
	reused, err := svc.CreateContinuationTemplate(ctx, input)
	require.NoError(t, err)
	require.Equal(t, template.ID, reused.ID)
	repo.templates[1][template.ID].Enabled = false
	_, err = svc.CreateContinuationTemplate(ctx, input)
	require.ErrorIs(t, err, ErrTemplateDisabled)
	require.Len(t, repo.templates[1], 1)
}

func TestInheritanceGenericTemplateEndpointRejectsClientProvenance(t *testing.T) {
	svc, _ := inheritanceFixture(t)
	projects := &fakeDiscoveryProjectAccess{project: &project.Project{ID: 1, TenantID: "tenant", OrgID: "org", Status: project.StatusActive}, role: asmcasbin.RoleProjectOwner}
	router := managementRouter(t, svc, projects)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/discovery/templates", strings.NewReader(`{"name":"forged","task_type":"dns","scope_id":1,"config":{"targets":[{"type":"domain","value":"api.example.com"}],"inheritance":{"source_run_id":10}},"enabled":true,"timeout_seconds":1800,"rate_limit":200,"concurrency":10}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "continuation endpoint")
}
