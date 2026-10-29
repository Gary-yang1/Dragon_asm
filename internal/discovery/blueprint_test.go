package discovery

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryBlueprintCatalogIsValidAndDefensivelyCopied(t *testing.T) {
	require.NoError(t, ValidateDiscoveryBlueprintCatalog())

	first := ListDiscoveryBlueprints()
	require.NotEmpty(t, first)
	first[0].Name = "mutated"
	first[0].RequiredTargetTypes[0] = TargetTypeURL
	first[0].Steps[0].Name = "mutated step"

	second := ListDiscoveryBlueprints()
	assert.NotEqual(t, "mutated", second[0].Name)
	assert.Equal(t, TargetTypeDomain, second[0].RequiredTargetTypes[0])
	assert.NotEqual(t, "mutated step", second[0].Steps[0].Name)
}

func TestPreviewDiscoveryBlueprintReportsReadyWithoutExternalCalls(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(
		repo,
		WithNow(func() time.Time { return now }),
		WithEngineRouter(NewTaskTypeEngineRouter(&fakeEngine{}, &fakeEngine{})),
		WithActiveDispatchPolicy(ActiveDispatchPolicy{Enabled: true}),
	)
	scope := putBlueprintScope(repo, 7, StatusActive, now, TargetTypeDomain, TargetTypeIP, TargetTypeURL)

	preview, err := svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{
		ProjectID: 7, ProjectStatus: "active", ScopeID: scope.ID, BlueprintKey: "asm_initial_baseline",
	})
	require.NoError(t, err)
	assert.True(t, preview.Ready)
	assert.Equal(t, BlueprintExecutionModePreviewOnly, preview.ExecutionMode)
	assert.Empty(t, preview.Issues)
	require.Len(t, preview.Steps, 4)
	for _, step := range preview.Steps {
		assert.True(t, step.Ready, step.Step.Key)
	}
}

func TestPreviewDiscoveryBlueprintRejectsMissingEngineProject(t *testing.T) {
	now := time.Now().UTC()
	repo := newFakeRepo()
	svc := NewService(repo, WithEngineRouter(NewTaskTypeEngineRouter(&fakeEngine{}, &ActiveAPIEngineAdapter{projectIDs: map[uint64]int{1: 1}})), WithActiveDispatchPolicy(ActiveDispatchPolicy{Enabled: true}))
	scope := putBlueprintScope(repo, 5, StatusActive, now, TargetTypeURL)
	preview, err := svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{ProjectID: 5, ProjectStatus: "active", ScopeID: scope.ID, BlueprintKey: "web_exposure_baseline"})
	require.NoError(t, err)
	assert.False(t, preview.Ready)
	found := false
	for _, issue := range preview.Issues {
		found = found || issue.Code == "ENGINE_PROJECT_MAPPING_MISSING"
	}
	assert.True(t, found)
}

func TestPreviewDiscoveryBlueprintAutomaticallySelectsDefaultOrOnlyCompatibleScope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return now }))

	first := putBlueprintScope(repo, 70, StatusActive, now, TargetTypeDomain)
	first.ID = 1
	first.IsDefault = false
	repo.scopes[70][first.ID] = first
	repo.targets[70][first.ID] = []*ScopeTarget{{
		ID: 1, ProjectID: 70, ScopeID: first.ID,
		TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com",
	}}
	defaultScope := &Scope{
		ID: 2, TenantID: "t", OrgID: "o", ProjectID: 70, Name: "default",
		Status: StatusActive, IsDefault: true, AuthorizedBy: "owner",
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
	}
	repo.scopes[70][defaultScope.ID] = defaultScope
	repo.targets[70][defaultScope.ID] = []*ScopeTarget{{
		ID: 2, ProjectID: 70, ScopeID: defaultScope.ID,
		TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.net",
	}}

	preview, err := svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{
		ProjectID: 70, ProjectStatus: "active", BlueprintKey: "domain_asset_inventory",
	})
	require.NoError(t, err)
	assert.Equal(t, defaultScope.ID, preview.Scope.ID)
	assert.Equal(t, BlueprintScopeSelectionDefault, preview.ScopeSelection)

	onlyCompatible := putBlueprintScope(repo, 71, StatusActive, now, TargetTypeIP)
	preview, err = svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{
		ProjectID: 71, ProjectStatus: "active", BlueprintKey: "ip_exposure_baseline",
	})
	require.NoError(t, err)
	assert.Equal(t, onlyCompatible.ID, preview.Scope.ID)
	assert.Equal(t, BlueprintScopeSelectionOnlyCompatible, preview.ScopeSelection)
}

func TestPreviewDiscoveryBlueprintRequiresSelectionOnlyWhenCompatibleScopesAreAmbiguous(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return now }))

	repo.scopes[72] = map[uint64]*Scope{}
	repo.targets[72] = map[uint64][]*ScopeTarget{}
	for id, name := range map[uint64]string{1: "first", 2: "second"} {
		repo.scopes[72][id] = &Scope{
			ID: id, TenantID: "t", OrgID: "o", ProjectID: 72, Name: name,
			Status: StatusActive, AuthorizedBy: "owner",
			ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
		}
		repo.targets[72][id] = []*ScopeTarget{{
			ID: id, ProjectID: 72, ScopeID: id,
			TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: name + ".example.com",
		}}
	}

	_, err := svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{
		ProjectID: 72, ProjectStatus: "active", BlueprintKey: "domain_asset_inventory",
	})
	assert.ErrorIs(t, err, ErrBlueprintScopeAmbiguous)

	_, err = svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{
		ProjectID: 73, ProjectStatus: "active", BlueprintKey: "domain_asset_inventory",
	})
	assert.ErrorIs(t, err, ErrBlueprintScopeUnavailable)
}

func TestPreviewDiscoveryBlueprintExplainsScopeEngineAndPolicyBlockers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return now }))
	scope := putBlueprintScope(repo, 8, StatusInactive, now, TargetTypeDomain)
	repo.targets[8][scope.ID] = append(repo.targets[8][scope.ID], &ScopeTarget{
		ID: 99, ProjectID: 8, ScopeID: scope.ID, TargetType: TargetTypeIP, MatchMode: MatchModeExclude, Value: "documentation-only",
	})

	preview, err := svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{
		ProjectID: 8, ProjectStatus: "suspended", ScopeID: scope.ID, BlueprintKey: "ip_exposure_baseline",
	})
	require.NoError(t, err)
	assert.False(t, preview.Ready)
	assert.Equal(t, []string{TargetTypeDomain}, preview.Scope.TargetTypes)
	assertIssueCodes(t, preview.Issues,
		BlueprintIssueProjectNotActive,
		BlueprintIssueScopeInactive,
		BlueprintIssueTargetTypeMissing,
		BlueprintIssueEngineNotConfigured,
		BlueprintIssueActiveNotEnabled,
	)
	require.Len(t, preview.Steps, 1)
	assert.False(t, preview.Steps[0].Ready)
}

func TestPreviewDiscoveryBlueprintRejectsUnknownBlueprintAndCrossProjectScope(t *testing.T) {
	now := time.Now().UTC()
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return now }))
	scope, err := svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID: "t", OrgID: "o", ProjectID: 9, Name: "scope", Status: StatusActive,
		AuthorizedBy: "owner", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), ActorID: "1",
		Targets: []ScopeTargetInput{{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com"}},
	})
	require.NoError(t, err)

	_, err = svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{
		ProjectID: 9, ProjectStatus: "active", ScopeID: scope.ID, BlueprintKey: "does_not_exist",
	})
	assert.ErrorIs(t, err, ErrBlueprintNotFound)

	_, err = svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{
		ProjectID: 10, ProjectStatus: "active", ScopeID: scope.ID, BlueprintKey: "domain_asset_inventory",
	})
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestPreviewDiscoveryBlueprintPropagatesDependencyBlockers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(
		repo,
		WithNow(func() time.Time { return now }),
		WithEngineRouter(NewTaskTypeEngineRouter(&fakeEngine{}, &fakeEngine{})),
		WithActiveDispatchPolicy(ActiveDispatchPolicy{Enabled: true}),
	)
	scope := putBlueprintScope(repo, 11, StatusActive, now, TargetTypeDomain, TargetTypeURL)

	preview, err := svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{
		ProjectID: 11, ProjectStatus: "active", ScopeID: scope.ID, BlueprintKey: "asm_initial_baseline",
	})
	require.NoError(t, err)
	require.Len(t, preview.Steps, 4)
	assert.False(t, preview.Steps[2].Ready)
	assertIssueCodes(t, preview.Steps[2].Issues, BlueprintIssueTargetTypeMissing)
	assert.False(t, preview.Steps[3].Ready)
	assertIssueCodes(t, preview.Steps[3].Issues, BlueprintIssueDependencyNotReady)
}

func TestCreateBlueprintTaskTemplatesIsManualAtomicAndIdempotent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	engine := &fakeEngine{}
	auditSink := &fakeAudit{}
	svc := NewService(
		repo,
		WithNow(func() time.Time { return now }),
		WithAuditSink(auditSink),
		WithEngineRouter(NewTaskTypeEngineRouter(engine, nil)),
	)
	scope := putBlueprintScope(repo, 15, StatusActive, now, TargetTypeDomain)
	repo.targets[15][scope.ID][0].Value = "example.com"

	input := CreateBlueprintTemplatesInput{
		TenantID: "tenant-a", OrgID: "org-a", ProjectID: 15, ProjectStatus: "active",
		ScopeID: scope.ID, BlueprintKey: "domain_asset_inventory", ActorID: "7",
	}
	first, err := svc.CreateBlueprintTaskTemplates(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, BlueprintExecutionModeTemplates, first.ExecutionMode)
	assert.Equal(t, 2, first.CreatedCount)
	assert.Zero(t, first.ExistingCount)
	require.Len(t, first.Templates, 2)
	assert.Len(t, repo.templates[15], 2)
	assert.Empty(t, repo.runs[15])
	assert.Zero(t, engine.dispatchCalls)
	assert.Len(t, auditSink.events, 2)

	for _, item := range first.Templates {
		assert.True(t, item.Created)
		assert.True(t, item.Template.Enabled)
		assert.Empty(t, item.Template.Schedule)
		var config struct {
			Targets []blueprintConfigTarget `json:"targets"`
			Options map[string]any          `json:"options"`
		}
		require.NoError(t, json.Unmarshal([]byte(item.Template.Config), &config))
		assert.Equal(t, "example.com", config.Targets[0].Value)
		assert.Equal(t, "domain_asset_inventory", config.Options["blueprint_key"])
		assert.Equal(t, "1.0.0", config.Options["blueprint_version"])
		assert.Equal(t, item.StepKey, config.Options["blueprint_step_key"])
	}

	second, err := svc.CreateBlueprintTaskTemplates(context.Background(), input)
	require.NoError(t, err)
	assert.Zero(t, second.CreatedCount)
	assert.Equal(t, 2, second.ExistingCount)
	assert.Len(t, repo.templates[15], 2)
	assert.Empty(t, repo.runs[15])
	assert.Zero(t, engine.dispatchCalls)
	assert.Len(t, auditSink.events, 2)
}

func TestCreateBlueprintTaskTemplatesRequiresReadyPreview(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := newFakeRepo()
	svc := NewService(
		repo,
		WithNow(func() time.Time { return now }),
		WithEngineRouter(NewTaskTypeEngineRouter(&fakeEngine{}, nil)),
	)
	scope := putBlueprintScope(repo, 16, StatusActive, now, TargetTypeDomain)

	_, err := svc.CreateBlueprintTaskTemplates(context.Background(), CreateBlueprintTemplatesInput{
		TenantID: "tenant-a", OrgID: "org-a", ProjectID: 16, ProjectStatus: "suspended",
		ScopeID: scope.ID, BlueprintKey: "domain_asset_inventory", ActorID: "7",
	})
	assert.ErrorIs(t, err, ErrBlueprintNotReady)
	assert.Empty(t, repo.templates[16])
	assert.Empty(t, repo.runs[16])
}

func assertIssueCodes(t *testing.T, issues []BlueprintPreviewIssue, expected ...string) {
	t.Helper()
	codes := make([]string, 0, len(issues))
	for _, issue := range issues {
		codes = append(codes, issue.Code)
	}
	for _, code := range expected {
		assert.Contains(t, codes, code)
	}
}

func putBlueprintScope(repo *fakeRepo, projectID uint64, status string, now time.Time, targetTypes ...string) *Scope {
	scope := &Scope{
		ID: 1, TenantID: "t", OrgID: "o", ProjectID: projectID, Name: "blueprint scope",
		Status: status, AuthorizedBy: "owner", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
	}
	repo.scopes[projectID] = map[uint64]*Scope{scope.ID: scope}
	repo.targets[projectID] = map[uint64][]*ScopeTarget{scope.ID: {}}
	for index, targetType := range targetTypes {
		value := "documentation-only"
		if targetType == TargetTypeURL {
			value = "https://example.com"
		}
		repo.targets[projectID][scope.ID] = append(repo.targets[projectID][scope.ID], &ScopeTarget{
			ID: uint64(index + 1), ProjectID: projectID, ScopeID: scope.ID,
			TargetType: targetType, MatchMode: MatchModeInclude, Value: value,
		})
	}
	return scope
}
