package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type webAssetFixtureRepo struct {
	*fakeRepo
	assets    []webBlueprintAsset
	projectID uint64
	cursors   []uint64
}

func (r *webAssetFixtureRepo) listWebBlueprintAssets(_ context.Context, projectID, afterID uint64) ([]webBlueprintAsset, error) {
	r.projectID = projectID
	r.cursors = append(r.cursors, afterID)
	result := []webBlueprintAsset{}
	for i, asset := range r.assets {
		asset.ID = uint64(i + 1)
		if asset.ID > afterID {
			result = append(result, asset)
			if len(result) == 1000 {
				break
			}
		}
	}
	return result, nil
}

func TestWebBlueprintRecognizesWildcardAuthorizationAndResolvesExistingHosts(t *testing.T) {
	svc, repo := inheritanceFixture(t)
	value, rule, err := normalizeURLAuthorization("http://*.example.com", nil)
	require.NoError(t, err)
	repo.targets[1][1] = append(repo.targets[1][1], &ScopeTarget{ID: 20, TargetType: TargetTypeURL, MatchMode: MatchModeInclude, Value: value, URLRule: rule})
	assets := &webAssetFixtureRepo{fakeRepo: repo, assets: []webBlueprintAsset{
		{Kind: "domain", Value: "example.com"}, {Kind: "subdomain", Value: "api.example.com"},
		{Kind: "subdomain", Value: "excluded.example.com"}, {Kind: "subdomain", Value: "example.com.evil.org"},
		{Kind: "web", Value: "https://api.example.com:8443/path"},
	}}
	svc.repo = assets
	svc.engineRouter = NewTaskTypeEngineRouter(&fakeEngine{}, &fakeEngine{})
	svc.activePolicy = ActiveDispatchPolicy{Enabled: true}
	input := PreviewBlueprintInput{ProjectID: 1, ProjectStatus: "active", BlueprintKey: "web_exposure_baseline"}
	preview, err := svc.PreviewDiscoveryBlueprint(context.Background(), input)
	require.NoError(t, err)
	require.True(t, preview.Ready)
	require.Equal(t, 1, *preview.Steps[0].TargetCount)
	require.Equal(t, []string{"http://api.example.com:80"}, preview.Steps[0].TargetExamples)
	require.Equal(t, uint64(1), assets.projectID)
	created, err := svc.CreateBlueprintTaskTemplates(context.Background(), CreateBlueprintTemplatesInput{ProjectID: 1, TenantID: "tenant", OrgID: "org", ScopeID: 1, ProjectStatus: "active", BlueprintKey: "web_exposure_baseline", ActorID: "1"})
	require.NoError(t, err)
	require.Len(t, created.Templates, 1)
	config, err := parseDispatchConfig(created.Templates[0].Template.Config)
	require.NoError(t, err)
	require.Equal(t, []DispatchTarget{{Type: TargetTypeURL, Value: "http://api.example.com:80"}}, config.Targets)
	assets.assets = nil
	preview, err = svc.PreviewDiscoveryBlueprint(context.Background(), input)
	require.NoError(t, err)
	require.False(t, preview.Ready)
	assert.Equal(t, "URL_TARGETS_EMPTY", preview.Steps[0].Issues[0].Code)
}

func TestWebBlueprintResolverIncludesAllPagesBeyondFormerLimits(t *testing.T) {
	svc, repo := inheritanceFixture(t)
	value, rule, err := normalizeURLAuthorization("https://*.example.com", nil)
	require.NoError(t, err)
	repo.targets[1][1] = append(repo.targets[1][1], &ScopeTarget{ID: 20, TargetType: TargetTypeURL, MatchMode: MatchModeInclude, Value: value, URLRule: rule})
	assets := &webAssetFixtureRepo{fakeRepo: repo}
	for i := 0; i < 5130; i++ {
		assets.assets = append(assets.assets, webBlueprintAsset{Kind: "subdomain", Value: fmt.Sprintf("host%d.example.com", i)})
	}
	svc.repo = assets
	scope, err := svc.GetScope(context.Background(), 1, 1)
	require.NoError(t, err)
	result, err := svc.resolveWebBlueprintTargets(context.Background(), scope)
	require.NoError(t, err)
	require.Len(t, result.URLs, 5130)
	require.False(t, result.Truncated)
	require.Equal(t, []uint64{0, 1000, 2000, 3000, 4000, 5000, 5130}, assets.cursors)
}

func TestWebBlueprintDomainGrantRespectsCoverageExclusionsAndSiteRules(t *testing.T) {
	for _, coverage := range []string{CoverageModeExact, CoverageModeSubdomains} {
		t.Run(coverage, func(t *testing.T) {
			svc, repo := inheritanceFixture(t)
			repo.targets[1][1][0].CoverageMode = coverage
			value, rule, err := normalizeURLAuthorization("https://secure.example.com", &URLAuthorizationRule{Protocol: "https", IncludeRoot: true, Ports: []uint16{8443}})
			require.NoError(t, err)
			repo.targets[1][1] = append(repo.targets[1][1], &ScopeTarget{TargetType: TargetTypeURL, MatchMode: MatchModeInclude, Value: value, URLRule: rule})
			svc.repo = &webAssetFixtureRepo{fakeRepo: repo, assets: []webBlueprintAsset{
				{Kind: "domain", Value: "example.com"}, {Kind: "subdomain", Value: "api.example.com"},
				{Kind: "subdomain", Value: "excluded.example.com"}, {Kind: "subdomain", Value: "a.excluded.example.com"},
				{Kind: "subdomain", Value: "example.com.evil.org"}, {Kind: "subdomain", Value: "secure.example.com"},
				{Kind: "web", Value: "https://example.com/path"}, {Kind: "web", Value: "https://api.example.com:8443/path"},
				{Kind: "web", Value: "http://1.1.1.1"},
			}}
			scope, err := svc.GetScope(context.Background(), 1, 1)
			require.NoError(t, err)
			result, err := svc.resolveWebBlueprintTargets(context.Background(), scope)
			require.NoError(t, err)
			expected := []string{"http://example.com:80", "https://example.com:443", "https://secure.example.com:8443"}
			if coverage == CoverageModeSubdomains {
				expected = append(expected, "http://api.example.com:80", "https://api.example.com:443", "https://api.example.com:8443")
			}
			require.ElementsMatch(t, expected, result.URLs)
			for _, value := range result.URLs {
				parsed, err := parseTarget(value)
				require.NoError(t, err)
				require.Equal(t, ReasonAllowed, scopeMatchDecision(scope.Targets, parsed))
			}
		})
	}
}

func TestWebBlueprintDeduplicatesSiteEndpointsUsingExistingURLModel(t *testing.T) {
	svc, repo := inheritanceFixture(t)
	values := []string{
		"https://api.example.com/app1", "https://api.example.com/app2",
		"https://api.example.com/app1?a=1", "https://api.example.com/app1?a=2",
		"https://api.example.com/app1/", "https://api.example.com/app%31",
		"https://api.example.com/app1?", "https://api.example.com",
		"https://api.example.com:443/app1", "https://api.example.com/", "https://api.example.com:443/",
		"http://api.example.com/app1", "http://api.example.com:80/app2",
		"https://api.example.com:8443/app1", "https://api.example.com:8443/app2",
	}
	repo.targets[1][1] = nil
	for _, value := range values {
		repo.targets[1][1] = append(repo.targets[1][1], &ScopeTarget{TargetType: TargetTypeURL, MatchMode: MatchModeInclude, Value: value})
	}
	scope, err := svc.GetScope(context.Background(), 1, 1)
	require.NoError(t, err)
	result, err := svc.resolveWebBlueprintTargets(context.Background(), scope)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"https://api.example.com", "http://api.example.com", "https://api.example.com:8443"}, result.URLs)
}

func TestWebBlueprintBatchesAllTargetsAndReusesMatchingSnapshots(t *testing.T) {
	svc, repo := inheritanceFixture(t)
	assets := &webAssetFixtureRepo{fakeRepo: repo}
	for i := 0; i < 1200; i++ {
		assets.assets = append(assets.assets, webBlueprintAsset{Kind: "subdomain", Value: fmt.Sprintf("host%04d.example.com", i)})
	}
	assets.assets[0].Value = "tokenhub.example.com" // A hostname is not a credential field.

	svc.repo = assets
	svc.engineRouter = NewTaskTypeEngineRouter(&fakeEngine{}, &fakeEngine{})
	svc.activePolicy = ActiveDispatchPolicy{Enabled: true}
	in := CreateBlueprintTemplatesInput{ProjectID: 1, TenantID: "tenant", OrgID: "org", ScopeID: 1, ProjectStatus: "active", BlueprintKey: "web_exposure_baseline", ActorID: "1"}
	preview, err := svc.PreviewDiscoveryBlueprint(context.Background(), PreviewBlueprintInput{ProjectID: 1, ProjectStatus: "active", BlueprintKey: in.BlueprintKey})
	require.NoError(t, err)
	require.True(t, preview.Ready)
	require.Equal(t, 2402, *preview.Steps[0].TargetCount)
	require.Equal(t, 3, preview.Steps[0].BatchCount)
	// A legacy manually generated 100-target snapshot must not be reused as
	// proof that a complete inventory snapshot has already been prepared.
	bp, err := GetDiscoveryBlueprint(in.BlueprintKey)
	require.NoError(t, err)
	scope, err := svc.GetScope(context.Background(), 1, 1)
	require.NoError(t, err)
	all, err := svc.resolveWebBlueprintTargets(context.Background(), scope)
	require.NoError(t, err)
	legacy, err := blueprintTaskConfig(bp, bp.Steps[0], scope, all.URLs[:100])
	require.NoError(t, err)
	var legacyConfig map[string]any
	require.NoError(t, json.Unmarshal([]byte(legacy), &legacyConfig))
	delete(legacyConfig["options"].(map[string]any), "target_selection")
	legacyBytes, err := json.Marshal(legacyConfig)
	require.NoError(t, err)
	repo.templates[1] = map[uint64]*TaskTemplate{99: {ID: 99, ProjectID: 1, ScopeID: 1, TaskType: TaskTypeWebProbe, Name: "legacy capped snapshot", Enabled: true, Config: string(legacyBytes)}}
	created, err := svc.CreateBlueprintTaskTemplates(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, created.Templates, 3)
	require.Equal(t, 2402, created.TargetCount)
	require.Equal(t, 3, created.CreatedCount)
	seen := map[string]bool{}
	for i, item := range created.Templates {
		require.NotEqual(t, uint64(99), item.Template.ID)
		require.Equal(t, i+1, item.BatchIndex)
		require.Equal(t, 3, item.BatchCount)
		require.LessOrEqual(t, len(item.Template.Config), maxTemplateConfigLen)
		config, err := parseDispatchConfig(item.Template.Config)
		require.NoError(t, err)
		require.Equal(t, item.TargetCount, len(config.Targets))
		require.LessOrEqual(t, len(config.Targets), activeAPIMaxTargets)
		require.Equal(t, "project_assets_snapshot_v2", config.Options["target_selection"])
		for _, target := range config.Targets {
			require.False(t, seen[target.Value])
			seen[target.Value] = true
		}
	}
	require.Len(t, seen, 2402)
	reused, err := svc.CreateBlueprintTaskTemplates(context.Background(), in)
	require.NoError(t, err)
	require.Equal(t, 3, reused.ExistingCount)
	require.Zero(t, reused.CreatedCount)
	require.Len(t, repo.runs[1], 1) // Only the pre-existing discovery run remains.
}

func TestWebBlueprintAssetRepositoryUsesProjectScopedKeyset(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	query := "SELECT id, asset_type, value FROM asset WHERE project_id = ? AND id > ? AND status = 'active' AND asset_type IN ('domain', 'subdomain', 'web') AND deleted_at = '1970-01-01 00:00:00.000' ORDER BY id LIMIT 1000"
	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs(uint64(7), uint64(5000)).WillReturnRows(sqlmock.NewRows([]string{"id", "asset_type", "value"}).AddRow(6001, "subdomain", "after-page.example.com"))
	repo := &sqlcRepository{q: dbgen.New(db)}
	rows, err := repo.listWebBlueprintAssets(context.Background(), 7, 5000)
	require.NoError(t, err)
	require.Equal(t, []webBlueprintAsset{{ID: 6001, Kind: "subdomain", Value: "after-page.example.com"}}, rows)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestWebBlueprintBatchingHonorsJSONByteLimit(t *testing.T) {
	bp, err := GetDiscoveryBlueprint("web_exposure_baseline")
	require.NoError(t, err)
	urls := []string{}
	for i := 0; i < 1000; i++ {
		urls = append(urls, fmt.Sprintf("https://%s.%s.%s.host%04d.example.com:443", strings.Repeat("a", 60), strings.Repeat("b", 60), strings.Repeat("c", 60), i))
	}
	scope := &Scope{ID: 1}
	batches, err := blueprintWebTargetBatches(bp, bp.Steps[0], scope, urls)
	require.NoError(t, err)
	require.Greater(t, len(batches), 1)
	all := []string{}
	for _, batch := range batches {
		config, err := blueprintTaskConfig(bp, bp.Steps[0], scope, batch)
		require.NoError(t, err)
		require.LessOrEqual(t, len(config), maxTemplateConfigLen)
		all = append(all, batch...)
	}
	require.Equal(t, urls, all)
}

func TestLargeWebSnapshotRemainsDispatchableAfterDatabaseJSONFormatting(t *testing.T) {
	targets := make([]map[string]string, 1000)
	for i := range targets {
		targets[i] = map[string]string{"type": "url", "value": fmt.Sprintf("http://hostaaaaa%d.example.com:80", i)}
	}
	raw, err := json.Marshal(map[string]any{"targets": targets, "options": map[string]any{}})
	require.NoError(t, err)
	require.LessOrEqual(t, len(raw), maxTemplateConfigLen)
	var databaseText bytes.Buffer
	require.NoError(t, json.Indent(&databaseText, raw, "", "  "))
	require.Greater(t, databaseText.Len(), maxTemplateConfigLen)
	template := toDomainTaskTemplate(dbgen.TaskTemplate{Config: databaseText.Bytes()})
	require.LessOrEqual(t, len(template.Config), maxTemplateConfigLen)
	require.NoError(t, validateActiveDispatchConfig(TaskTypeWebProbe, template.Config))
	parsed, err := parseDispatchConfig(template.Config)
	require.NoError(t, err)
	require.Len(t, parsed.Targets, 1000)
}
