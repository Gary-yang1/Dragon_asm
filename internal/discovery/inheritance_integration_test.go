package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Requires a disposable database. No application data or external engines are used.
func TestInheritanceMySQL(t *testing.T) {
	raw := os.Getenv("ASM_INHERITANCE_TEST_DSN")
	if raw == "" {
		t.Skip("dedicated inheritance test database not configured")
	}
	cfg, err := mysql.ParseDSN(raw)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(cfg.DBName, "asm_inheritance_test_"))
	cfg.MultiStatements = true
	cfg.ParseTime = true
	database, err := sql.Open("mysql", cfg.FormatDSN())
	require.NoError(t, err)
	defer database.Close()
	paths, err := filepath.Glob("../../migrations/*.up.sql")
	require.NoError(t, err)
	for _, path := range paths {
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		_, err = database.Exec(string(body))
		require.NoError(t, err, filepath.Base(path))
	}
	sourceID := seedEngineSettingsTestRun(t, database)
	_, err = database.Exec("UPDATE task_run SET status='success' WHERE id=?", sourceID)
	require.NoError(t, err)
	repo := NewRepository(dbgen.New(database))
	ctx := context.Background()
	require.NoError(t, repo.InsertScopeTarget(ctx, InsertScopeTargetParams{TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, ScopeID: 1, TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, CoverageMode: CoverageModeSubdomains, Value: "example.com", ActorID: "1"}))
	ids := []uint64{}
	for _, value := range []string{"api.example.com", "other.example.org", "excluded.example.com"} {
		fact, _ := json.Marshal(callbackAssetV1{AssetType: "subdomain", Value: value})
		observation, err := repo.UpsertDiscoveryObservation(ctx, DiscoveryObservation{TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, RunID: sourceID, Seq: 1, Kind: ObservationKindAsset, NaturalKey: "subdomain:" + value, Provider: "fixture", Capability: "subdomain_passive", ObservedAt: time.Now().UTC().Truncate(time.Millisecond), Confidence: 90, EvidenceHash: strings.Repeat("a", 64), NormalizedJSON: fact, IngestStatus: ObservationStatusMaterialized})
		require.NoError(t, err)
		ids = append(ids, observation.ID)
	}
	require.NoError(t, repo.InsertScopeTarget(ctx, InsertScopeTargetParams{TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, ScopeID: 1, TargetType: TargetTypeDomain, MatchMode: MatchModeExclude, CoverageMode: CoverageModeExact, Value: "excluded.example.com", ActorID: "1"}))
	svc := NewService(repo, WithDB(database))
	page, err := svc.ListDerivedTargets(ctx, 1, sourceID, 0)
	require.NoError(t, err)
	require.Len(t, page.Items, 3)
	input := CreateContinuationInput{ProjectID: 1, SourceRunID: sourceID, TaskType: TaskTypeDNS, ObservationIDs: ids[:1], ScopeFingerprint: page.ScopeFingerprint, ActorID: "1"}
	template, err := svc.CreateContinuationTemplate(ctx, input)
	require.NoError(t, err)
	reused, err := svc.CreateContinuationTemplate(ctx, input)
	require.NoError(t, err)
	require.Equal(t, template.ID, reused.ID)
	run, err := svc.CreateTaskRun(ctx, CreateTaskRunInput{ProjectID: 1, TemplateID: template.ID, ActorID: "1"})
	require.NoError(t, err)
	_, err = svc.BuildDispatchPlan(ctx, 1, run.ID, "1")
	require.NoError(t, err)
	// A late invalid selection rolls back earlier insertions in the same batch.
	_, err = svc.AuthorizeDerivedTargets(ctx, AuthorizeDerivedInput{ProjectID: 1, SourceRunID: sourceID, ObservationIDs: ids[1:], ScopeFingerprint: page.ScopeFingerprint, Reason: "transaction rollback", ActorID: "1"})
	require.ErrorIs(t, err, ErrInheritanceNotReady)
	// Structured URL rules survive SQL persistence; rollback disables affected
	// scopes before removing the rules, so legacy matching cannot broaden them.
	now := time.Now().UTC().Truncate(time.Millisecond)
	site, err := svc.CreateScope(ctx, CreateScopeInput{ProjectID: 1, TenantID: "tenant-e2e", OrgID: "org-e2e", Name: "URL rules", Status: StatusActive, AuthorizedBy: "owner", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), ActorID: "1", Targets: []ScopeTargetInput{
		{TargetType: TargetTypeURL, MatchMode: MatchModeInclude, Value: "https://*.site.example.org", URLRule: &URLAuthorizationRule{Protocol: "both", IncludeRoot: true, IncludeSubdomains: true, Ports: []uint16{8443}}},
	}})
	require.NoError(t, err)
	stored, err := svc.GetScope(ctx, 1, site.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.Targets[0].URLRule)
	allowed, _, err := svc.IsTypedTargetAllowed(ctx, 1, site.ID, TargetTypeURL, "http://api.site.example.org:8443/a")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, _, err = svc.IsTypedTargetAllowed(ctx, 1, site.ID, TargetTypeURL, "https://api.site.example.org")
	require.NoError(t, err)
	require.False(t, allowed)
	_, err = asset.NewService(asset.NewRepository(dbgen.New(database))).Import(ctx, asset.ImportInput{TenantID: "tenant-e2e", OrgID: "org-e2e", ProjectID: 1, AssetType: "subdomain", Value: "app.site.example.org", Source: "manual", Status: asset.StatusActive, ActorID: "1", Confidence: 90})
	require.NoError(t, err)
	resolved, err := svc.resolveWebBlueprintTargets(ctx, stored)
	require.NoError(t, err)
	require.Contains(t, resolved.URLs, "http://app.site.example.org:8443")
	require.Len(t, resolved.URLs, 4)
	scope, err := svc.GetScope(ctx, 1, 1)
	require.NoError(t, err)
	require.Len(t, scope.Targets, 2)
	// Concurrent confirmation from the same revision cannot silently overwrite scope.
	var group sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := svc.AuthorizeDerivedTargets(ctx, AuthorizeDerivedInput{ProjectID: 1, SourceRunID: sourceID, ObservationIDs: ids[1:2], ScopeFingerprint: page.ScopeFingerprint, Reason: "explicit confirmation", ActorID: "1"})
			results <- err
		}()
	}
	group.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, ErrInheritanceScopeChanged)
			conflicts++
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, conflicts)
	var metadata string
	require.NoError(t, database.QueryRow("SELECT metadata_json FROM audit_log WHERE action='scope.update' ORDER BY id DESC LIMIT 1").Scan(&metadata))
	require.Contains(t, metadata, "SourceObservationIDs")
	require.Contains(t, metadata, "explicit confirmation")
	require.NoError(t, svc.DeactivateScope(ctx, DeactivateScopeInput{ProjectID: 1, ScopeID: 1, ActorID: "1"}))
	_, err = svc.BuildDispatchPlan(ctx, 1, run.ID, "1")
	require.ErrorIs(t, err, ErrInheritanceNotReady)
	down, err := os.ReadFile("../../migrations/000032_url_authorization_rules.down.sql")
	require.NoError(t, err)
	_, err = database.Exec(string(down))
	require.NoError(t, err)
	var state string
	require.NoError(t, database.QueryRow("SELECT status FROM scope WHERE id=?", site.ID).Scan(&state))
	require.Equal(t, StatusInactive, state)
	up, err := os.ReadFile("../../migrations/000032_url_authorization_rules.up.sql")
	require.NoError(t, err)
	_, err = database.Exec(string(up))
	require.NoError(t, err)
}
