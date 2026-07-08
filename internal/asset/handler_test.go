package asset_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

// fakeProjectRepo is an in-memory project.Repository for handler tests. A user's
// membership and role are both keyed by "<projectID>:<userID>"; the role is what
// the handler feeds to the seeded Casbin matrix for action RBAC.
type fakeProjectRepo struct {
	projects map[uint64]*project.Project
	roles    map[string]string // "<projectID>:<userID>" -> role
}

func (f *fakeProjectRepo) GetByID(_ context.Context, id uint64) (*project.Project, error) {
	if p, ok := f.projects[id]; ok {
		return p, nil
	}
	return nil, project.ErrNotFound
}

func (f *fakeProjectRepo) GetByCode(_ context.Context, _, _ string) (*project.Project, error) {
	return nil, project.ErrNotFound
}

func (f *fakeProjectRepo) IsMember(_ context.Context, projectID uint64, userID string) (bool, error) {
	_, ok := f.roles[fmt.Sprintf("%d:%s", projectID, userID)]
	return ok, nil
}

func (f *fakeProjectRepo) MemberRole(_ context.Context, projectID uint64, userID string) (string, error) {
	role, ok := f.roles[fmt.Sprintf("%d:%s", projectID, userID)]
	if !ok {
		return "", project.ErrNotFound
	}
	return role, nil
}

// fakeAudit captures audit events for assertions. If err is set, Record returns
// it (without appending) to simulate an audit-store outage.
type fakeAudit struct {
	events []audit.Event
	err    error
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, e)
	return nil
}

// testEnv wires the handler with an in-memory asset repo, a project service
// backed by a fake project repo (membership+role based access), a Casbin enforcer
// seeded with the MVP role→permission matrix, and a fake audit recorder injected
// into the asset service (non-tx test path). The test user "1" is a member of the
// listed projects with the configured role.
type testEnv struct {
	handler   *asset.Handler
	assetRepo *fakeRepo
	projects  *fakeProjectRepo
	enforcer  *casbin.Enforcer
	audit     *fakeAudit
	engine    *gin.Engine
}

// newTestEnv makes the test user a member of the listed projects with the
// security_ops role (asset:read + asset:write), so the allow-path tests pass.
func newTestEnv(t *testing.T, memberOf ...uint64) *testEnv {
	return newTestEnvWithRole(t, asmcasbin.RoleSecurityOps, memberOf...)
}

// newTestEnvWithRole makes the test user a member of the listed projects with the
// given role, so a test can exercise denial (e.g. viewer lacks asset:write).
func newTestEnvWithRole(t *testing.T, role string, memberOf ...uint64) *testEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	assetRepo := newFakeRepo()
	projects := &fakeProjectRepo{
		projects: map[uint64]*project.Project{
			1: {ID: 1, TenantID: "t1", OrgID: "o1", Status: project.StatusActive},
			2: {ID: 2, TenantID: "t1", OrgID: "o1", Status: project.StatusActive},
		},
		roles: map[string]string{},
	}
	for _, pid := range memberOf {
		projects.roles[fmt.Sprintf("%d:1", pid)] = role // test user id is "1"
	}

	// Seed the production MVP matrix so permit() resolves role→perm exactly as in
	// the real wiring (no separate test-only policy seeding).
	enforcer, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	require.NoError(t, asmcasbin.SeedMVPolicies(enforcer))

	projectSvc := project.NewService(projects, enforcer)
	auditSink := &fakeAudit{}
	// WithAuditSink wires the non-tx audit path so handler tests can assert on
	// audit events without a real database transaction.
	assetSvc := asset.NewService(assetRepo, asset.WithAuditSink(auditSink))

	h := asset.NewHandler(assetSvc, projectSvc, enforcer, nil)

	r := gin.New()
	// Simulate an authenticated user (auth.RequireAuth already ran in production).
	r.Use(func(c *gin.Context) { c.Set(auth.CtxUserID, "1"); c.Next() })
	api := r.Group("/api/v1")
	h.RegisterRoutes(api)

	return &testEnv{handler: h, assetRepo: assetRepo, projects: projects, enforcer: enforcer, audit: auditSink, engine: r}
}

// newTestEnvGlobalRole wires a user who is NOT a project_member of any project
// but holds a global Casbin role via a grouping policy (the cross-project admin
// path). This exercises permit's explicit/global path: Access admits the user
// via project:access and permit grants asset:* via the user→role grouping
// resolved against the seeded matrix.
func newTestEnvGlobalRole(t *testing.T, role string) *testEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	assetRepo := newFakeRepo()
	// No membership roles: the user reaches the project only via the global role.
	projects := &fakeProjectRepo{
		projects: map[uint64]*project.Project{
			1: {ID: 1, TenantID: "t1", OrgID: "o1", Status: project.StatusActive},
		},
		roles: map[string]string{},
	}

	enforcer, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	require.NoError(t, asmcasbin.SeedMVPolicies(enforcer))
	// Assign the test user the global role (grouping in the "*" domain).
	_, err = enforcer.AddGroupingPolicy("1", role, asmcasbin.GlobalDomain)
	require.NoError(t, err)

	projectSvc := project.NewService(projects, enforcer)
	auditSink := &fakeAudit{}
	assetSvc := asset.NewService(assetRepo, asset.WithAuditSink(auditSink))
	h := asset.NewHandler(assetSvc, projectSvc, enforcer, nil)

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(auth.CtxUserID, "1"); c.Next() })
	api := r.Group("/api/v1")
	h.RegisterRoutes(api)

	return &testEnv{handler: h, assetRepo: assetRepo, projects: projects, enforcer: enforcer, audit: auditSink, engine: r}
}

func do(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// unwrap parses the unified envelope's data field into out.
func unwrap(t *testing.T, w *httptest.ResponseRecorder, out any) {
	t.Helper()
	var env struct {
		Data  json.RawMessage `json:"data"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	if out != nil && len(env.Data) > 0 {
		require.NoError(t, json.Unmarshal(env.Data, out))
	}
}

// assetJSON mirrors the handler's assetResponse with the fields tests assert on.
type assetJSON struct {
	ID     uint64 `json:"id"`
	Owner  string `json:"owner"`
	Status string `json:"status"`
}

// Acceptance: list returns a paginated, project-scoped page with a total.
func TestHandlerList(t *testing.T) {
	env := newTestEnv(t, 1)
	seedAsset(env.assetRepo, 10, 1, "domain:a.com", asset.StatusActive)
	seedAsset(env.assetRepo, 11, 1, "domain:b.com", asset.StatusActive)
	seedAsset(env.assetRepo, 12, 2, "domain:c.com", asset.StatusActive) // other project

	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/1/assets?page_size=10", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var page struct {
		Items []assetJSON `json:"items"`
		Total int64       `json:"total"`
	}
	unwrap(t, w, &page)
	assert.Equal(t, int64(2), page.Total, "total excludes the other project's asset")
	assert.Len(t, page.Items, 2)
}

// Detail returns the asset; a missing asset is 404.
func TestHandlerDetail(t *testing.T) {
	env := newTestEnv(t, 1)
	seedAsset(env.assetRepo, 10, 1, "domain:a.com", asset.StatusActive)

	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/1/assets/10", nil)
	require.Equal(t, http.StatusOK, w.Code)

	w = do(t, env.engine, http.MethodGet, "/api/v1/projects/1/assets/9999", nil)
	require.Equal(t, http.StatusNotFound, w.Code)
}

// Cross-project detail: even with project access, an asset from another project
// is not visible (asset-level project scoping).
func TestHandlerDetailCrossProject(t *testing.T) {
	env := newTestEnv(t, 1, 2)                                          // member of both projects
	seedAsset(env.assetRepo, 10, 1, "domain:a.com", asset.StatusActive) // lives in project 1

	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/2/assets/10", nil)
	require.Equal(t, http.StatusNotFound, w.Code, "asset from project 1 is not found in project 2")
}

// dry_run preview classifies rows and writes nothing.
func TestHandlerImportDryRun(t *testing.T) {
	env := newTestEnv(t, 1)
	body := map[string]any{"rows": []map[string]any{
		{"asset_type": "domain", "value": "new.com"},
		{"asset_type": "ip", "value": "not-an-ip"},
	}}
	w := do(t, env.engine, http.MethodPost, "/api/v1/projects/1/assets/import?dry_run=true", body)
	require.Equal(t, http.StatusOK, w.Code)

	var report asset.DryRunReport
	unwrap(t, w, &report)
	assert.Equal(t, int64(2), report.Total)
	assert.Equal(t, int64(1), report.New)
	assert.Equal(t, int64(1), report.Failed)
	assert.Empty(t, env.assetRepo.rows, "dry-run must not persist anything")
	assert.Empty(t, env.audit.events, "dry-run must not audit a write")
}

// Real import commits and audits.
func TestHandlerImportCommitsAndAudits(t *testing.T) {
	env := newTestEnv(t, 1)
	body := map[string]any{"rows": []map[string]any{
		{"asset_type": "domain", "value": "example.com", "source": "seed"},
	}}
	w := do(t, env.engine, http.MethodPost, "/api/v1/projects/1/assets/import", body)
	require.Equal(t, http.StatusOK, w.Code)

	var report asset.ImportBatchReport
	unwrap(t, w, &report)
	assert.Equal(t, int64(1), report.Success)
	assert.Len(t, env.assetRepo.rows, 1, "real import persists the asset")
	require.Len(t, env.audit.events, 1)
	assert.Equal(t, asset.ActionAssetImport, env.audit.events[0].Action)
	assert.Equal(t, "asset", env.audit.events[0].ResourceType)
	assert.Equal(t, audit.ResultSuccess, env.audit.events[0].Result)
}

// A malformed import body (missing required row fields) is 400, not a per-row failure.
func TestHandlerImportBadBody(t *testing.T) {
	env := newTestEnv(t, 1)
	body := map[string]any{"rows": []map[string]any{
		{"value": "no-type.com"}, // missing required asset_type
	}}
	w := do(t, env.engine, http.MethodPost, "/api/v1/projects/1/assets/import", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Update edits a field and audits the change.
func TestHandlerUpdate(t *testing.T) {
	env := newTestEnv(t, 1)
	seedAsset(env.assetRepo, 10, 1, "domain:a.com", asset.StatusActive)

	body := map[string]any{"owner": "bob", "status": "ignored"}
	w := do(t, env.engine, http.MethodPatch, "/api/v1/projects/1/assets/10", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp assetJSON
	unwrap(t, w, &resp)
	assert.Equal(t, "bob", resp.Owner)
	assert.Equal(t, "ignored", resp.Status)
	require.Len(t, env.audit.events, 1)
	assert.Equal(t, asset.ActionAssetUpdate, env.audit.events[0].Action)
}

// Update with 'deleted' status is rejected (reserved for soft-delete).
func TestHandlerUpdateRejectsDeletedStatus(t *testing.T) {
	env := newTestEnv(t, 1)
	seedAsset(env.assetRepo, 10, 1, "domain:a.com", asset.StatusActive)

	body := map[string]any{"status": "deleted"}
	w := do(t, env.engine, http.MethodPatch, "/api/v1/projects/1/assets/10", body)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// Update on a missing asset is 404.
func TestHandlerUpdateNotFound(t *testing.T) {
	env := newTestEnv(t, 1)
	body := map[string]any{"owner": "bob"}
	w := do(t, env.engine, http.MethodPatch, "/api/v1/projects/1/assets/9999", body)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// Project isolation: a user who is not a member of the project is forbidden.
func TestHandlerAccessDeniedForbidden(t *testing.T) {
	env := newTestEnv(t, 1) // member of project 1 only
	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/2/assets", nil)
	assert.Equal(t, http.StatusForbidden, w.Code, "non-member is denied")
}

// Unknown project is 404, not 403 (no access-oracle leak).
func TestHandlerUnknownProjectNotFound(t *testing.T) {
	env := newTestEnv(t, 1)
	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/9999/assets", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// Invalid path params are 400.
func TestHandlerInvalidPathParams(t *testing.T) {
	env := newTestEnv(t, 1)
	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/abc/assets", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	w = do(t, env.engine, http.MethodGet, "/api/v1/projects/1/assets/notanumber", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Oversized pagination is rejected (page_size > MaxPageSize is never clamped).
func TestHandlerListRejectsOversizedPage(t *testing.T) {
	env := newTestEnv(t, 1)
	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/1/assets?page_size=9999", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// A viewer (read-only role) can read assets but is denied asset:write — the
// matrix differentiates read vs write per role. Non-member read denial is
// covered by TestHandlerAccessDeniedForbidden.
func TestHandlerViewerCanReadCannotWrite(t *testing.T) {
	env := newTestEnvWithRole(t, asmcasbin.RoleViewer, 1) // viewer member of project 1

	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/1/assets", nil)
	assert.Equal(t, http.StatusOK, w.Code, "viewer can asset:read")

	body := map[string]any{"rows": []map[string]any{
		{"asset_type": "domain", "value": "example.com"},
	}}
	w = do(t, env.engine, http.MethodPost, "/api/v1/projects/1/assets/import", body)
	assert.Equal(t, http.StatusForbidden, w.Code, "viewer is denied asset:write")
	assert.Empty(t, env.assetRepo.rows, "denied import writes nothing")
	assert.Empty(t, env.audit.events, "denied import is not audited")
}

// A project member without the asset:write permission is denied update too.
func TestHandlerAssetWriteDeniedOnUpdate(t *testing.T) {
	env := newTestEnvWithRole(t, asmcasbin.RoleViewer, 1)
	seedAsset(env.assetRepo, 10, 1, "domain:a.com", asset.StatusActive)

	body := map[string]any{"owner": "bob"}
	w := do(t, env.engine, http.MethodPatch, "/api/v1/projects/1/assets/10", body)
	assert.Equal(t, http.StatusForbidden, w.Code, "viewer is denied asset:write (update)")
}

// Audit-write failure for an import is treated as a failed request, not silent.
func TestHandlerImportAuditFailureFails(t *testing.T) {
	env := newTestEnv(t, 1)
	env.audit.err = errors.New("audit store down")
	body := map[string]any{"rows": []map[string]any{
		{"asset_type": "domain", "value": "example.com"},
	}}
	w := do(t, env.engine, http.MethodPost, "/api/v1/projects/1/assets/import", body)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "audit failure must fail the request")
	assert.Empty(t, env.audit.events, "no audit event was persisted on failure")
}

// Audit-write failure for an update is treated as a failed request, not silent.
func TestHandlerUpdateAuditFailureFails(t *testing.T) {
	env := newTestEnv(t, 1)
	seedAsset(env.assetRepo, 10, 1, "domain:a.com", asset.StatusActive)
	env.audit.err = errors.New("audit store down")

	body := map[string]any{"owner": "bob"}
	w := do(t, env.engine, http.MethodPatch, "/api/v1/projects/1/assets/10", body)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "audit failure must fail the request")
	assert.Empty(t, env.audit.events)
}

// Import audit result reflects partial failure: any failed row => failure result.
func TestHandlerImportAuditResultPartialFailure(t *testing.T) {
	env := newTestEnv(t, 1)
	body := map[string]any{"rows": []map[string]any{
		{"asset_type": "domain", "value": "ok.com"},
		{"asset_type": "ip", "value": "not-an-ip"}, // fails
	}}
	w := do(t, env.engine, http.MethodPost, "/api/v1/projects/1/assets/import", body)
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, env.audit.events, 1)
	assert.Equal(t, audit.ResultFailure, env.audit.events[0].Result, "a failed row yields a failure audit result")
}

// A global role (no project_member row) reaches a project via project:access and
// is granted asset:read/asset:write through the user→role grouping resolved
// against the seeded matrix — the explicit/global Casbin path in permit.
func TestHandlerGlobalRoleCanAccessAssets(t *testing.T) {
	env := newTestEnvGlobalRole(t, asmcasbin.RoleSecurityAdmin) // not a member; global security_admin
	seedAsset(env.assetRepo, 10, 1, "domain:a.com", asset.StatusActive)

	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/1/assets", nil)
	require.Equal(t, http.StatusOK, w.Code, "global security_admin can asset:read via explicit path")

	body := map[string]any{"rows": []map[string]any{
		{"asset_type": "domain", "value": "imported.com"},
	}}
	w = do(t, env.engine, http.MethodPost, "/api/v1/projects/1/assets/import", body)
	require.Equal(t, http.StatusOK, w.Code, "global security_admin can asset:write via explicit path")
	require.Len(t, env.audit.events, 1, "the global-role import is still audited")
}

// A global role whose matrix role lacks project:access (e.g. viewer is a
// project-scoped role, not a cross-project one) cannot reach the project at all
// — Access denies it before permit, so asset APIs are 403. This guards against
// accidentally granting cross-project access to project-scoped roles.
func TestHandlerGlobalProjectScopedRoleDeniedAccess(t *testing.T) {
	env := newTestEnvGlobalRole(t, asmcasbin.RoleViewer) // global grouping to a project-scoped role

	w := do(t, env.engine, http.MethodGet, "/api/v1/projects/1/assets", nil)
	assert.Equal(t, http.StatusForbidden, w.Code, "project-scoped role has no project:access -> 403")
}
