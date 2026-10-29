package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

// fakeProjectRepo is an in-memory project.Repository. Membership and role are
// keyed by "<projectID>:<userID>"; the role is what the handler feeds to the
// seeded Casbin matrix for action RBAC.
type fakeProjectRepo struct {
	projects map[uint64]*project.Project
	roles    map[string]string
}

func (f *fakeProjectRepo) ActorScope(_ context.Context, _ string) (project.ActorScope, error) {
	return project.ActorScope{TenantID: "t1", OrgID: "o1"}, nil
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

type riskHandlerEnv struct {
	engine   *gin.Engine
	svc      *Service
	repo     *fakeRepo
	enforcer *casbin.Enforcer
}

// newRiskHandlerEnv wires the real handler against in-memory stores, with the
// production MVP role→permission matrix seeded so authorization resolves exactly
// as it does in cmd/api. The test user is "1", a member of project 1 with role.
func newRiskHandlerEnv(t *testing.T, role string) *riskHandlerEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	repo := newFakeRepo()
	svc := NewService(repo, WithAuditSink(repo), WithNow(func() time.Time {
		return time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	}))

	projects := &fakeProjectRepo{
		projects: map[uint64]*project.Project{
			1: {ID: 1, TenantID: "t1", OrgID: "o1", Status: project.StatusActive},
			2: {ID: 2, TenantID: "t1", OrgID: "o1", Status: project.StatusActive},
		},
		roles: map[string]string{"1:1": role},
	}

	enforcer, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	require.NoError(t, asmcasbin.SeedMVPolicies(enforcer))

	h := NewHandler(svc, project.NewService(projects, enforcer), enforcer)

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(auth.CtxUserID, "1"); c.Next() })
	h.RegisterRoutes(r.Group("/api/v1"))

	return &riskHandlerEnv{engine: r, svc: svc, repo: repo, enforcer: enforcer}
}

func (e *riskHandlerEnv) transition(t *testing.T, projectID, riskID uint64, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/risks/%d/status-transitions", projectID, riskID),
		bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.engine.ServeHTTP(w, req)
	return w
}

// A role holding risk:write but not risk:accept must not be able to retire a risk
// as accepted. Before the action-specific gate, risk:write alone reached
// risk_accepted through this endpoint.
func TestTransitionStatusRequiresRiskAcceptPermission(t *testing.T) {
	env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityOps)
	require.False(t, env.enforcer.HasPolicy(asmcasbin.RoleSecurityOps, asmcasbin.GlobalDomain, asmcasbin.PermRiskAccept, "allow"),
		"precondition: security_ops must not hold risk:accept")
	require.True(t, env.enforcer.HasPolicy(asmcasbin.RoleSecurityOps, asmcasbin.GlobalDomain, asmcasbin.PermRiskWrite, "allow"),
		"precondition: security_ops must hold risk:write")

	r := createRiskByRule(t, env.svc)

	// Ordinary triage is still allowed with risk:write alone.
	w := env.transition(t, 1, r.ID, map[string]any{"action": StatusActionConfirm, "reason": "triaged"})
	require.Equal(t, http.StatusOK, w.Code, "confirm must remain available to risk:write: %s", w.Body.String())

	w = env.transition(t, 1, r.ID, map[string]any{
		"action": StatusActionAccept, "reason": "business accepts", "approved_by": "carol",
		"expires_at": "2026-12-31T00:00:00Z", "review_required_at": "2026-10-01T00:00:00Z",
	})
	assert.Equal(t, http.StatusForbidden, w.Code, "accept must require risk:accept")
	assert.Contains(t, w.Body.String(), "FORBIDDEN")

	// The risk must not have moved.
	after, err := env.svc.GetByID(context.Background(), 1, r.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusConfirmed, after.Status, "a denied transition must not mutate the risk")
}

// false_positive buries a finding, so it is gated on risk:suppress. project_owner
// holds risk:accept but deliberately not risk:suppress in the seeded matrix.
func TestTransitionStatusRequiresRiskSuppressForFalsePositive(t *testing.T) {
	env := newRiskHandlerEnv(t, asmcasbin.RoleProjectOwner)
	require.True(t, env.enforcer.HasPolicy(asmcasbin.RoleProjectOwner, asmcasbin.GlobalDomain, asmcasbin.PermRiskAccept, "allow"))
	require.False(t, env.enforcer.HasPolicy(asmcasbin.RoleProjectOwner, asmcasbin.GlobalDomain, asmcasbin.PermRiskSuppress, "allow"))

	r := createRiskByRule(t, env.svc)

	w := env.transition(t, 1, r.ID, map[string]any{
		"action": StatusActionFalsePositive, "reason": "not exploitable", "approved_by": "carol",
		"expires_at": "2026-12-31T00:00:00Z", "review_required_at": "2026-10-01T00:00:00Z",
	})
	assert.Equal(t, http.StatusForbidden, w.Code, "false_positive must require risk:suppress")

	// The same role may still accept, proving the two permissions are distinct.
	w = env.transition(t, 1, r.ID, map[string]any{"action": StatusActionConfirm, "reason": "triaged"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = env.transition(t, 1, r.ID, map[string]any{
		"action": StatusActionAccept, "reason": "business accepts", "approved_by": "carol",
		"expires_at": "2026-12-31T00:00:00Z", "review_required_at": "2026-10-01T00:00:00Z",
	})
	assert.Equal(t, http.StatusOK, w.Code, "project_owner holds risk:accept: %s", w.Body.String())
}

// security_admin holds both elevated permissions, so the whole decision path works.
func TestTransitionStatusAllowsAcceptForPrivilegedRole(t *testing.T) {
	env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityAdmin)
	r := createRiskByRule(t, env.svc)

	require.Equal(t, http.StatusOK,
		env.transition(t, 1, r.ID, map[string]any{"action": StatusActionConfirm, "reason": "triaged"}).Code)

	w := env.transition(t, 1, r.ID, map[string]any{
		"action": StatusActionAccept, "reason": "compensating control in place", "approved_by": "carol",
		"expires_at": "2026-12-31T00:00:00Z", "review_required_at": "2026-10-01T00:00:00Z",
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	after, err := env.svc.GetByID(context.Background(), 1, r.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusRiskAccepted, after.Status)
}

// Separation of duties: the actor cannot name themselves as the approver of their
// own risk acceptance. The test user's ID is "1".
func TestTransitionStatusRejectsSelfApproval(t *testing.T) {
	env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityAdmin)
	r := createRiskByRule(t, env.svc)
	require.Equal(t, http.StatusOK,
		env.transition(t, 1, r.ID, map[string]any{"action": StatusActionConfirm, "reason": "triaged"}).Code)

	body := map[string]any{
		"action": StatusActionAccept, "reason": "we accept this",
		"expires_at": "2026-12-31T00:00:00Z", "review_required_at": "2026-10-01T00:00:00Z",
	}

	body["approved_by"] = "1" // the caller
	w := env.transition(t, 1, r.ID, body)
	assert.Equal(t, http.StatusBadRequest, w.Code, "self-approval must be rejected: %s", w.Body.String())

	after, err := env.svc.GetByID(context.Background(), 1, r.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusConfirmed, after.Status, "a rejected decision must not mutate the risk")

	// A distinct approver is accepted.
	body["approved_by"] = "2"
	w = env.transition(t, 1, r.ID, body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	after, err = env.svc.GetByID(context.Background(), 1, r.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusRiskAccepted, after.Status)
}

// A read-only role must not transition at all, and the denial must come from the
// permission layer rather than the request body.
func TestTransitionStatusDeniesViewer(t *testing.T) {
	env := newRiskHandlerEnv(t, asmcasbin.RoleViewer)
	r := createRiskByRule(t, env.svc)

	w := env.transition(t, 1, r.ID, map[string]any{"action": StatusActionConfirm, "reason": "triaged"})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// Project scoping: a member of project 1 must not reach project 2's risks, and the
// response must not reveal whether the risk exists there.
func TestTransitionStatusDeniesNonMemberProject(t *testing.T) {
	env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityAdmin)
	r := createRiskByRule(t, env.svc)

	w := env.transition(t, 2, r.ID, map[string]any{"action": StatusActionConfirm, "reason": "triaged"})
	assert.Equal(t, http.StatusForbidden, w.Code, "non-member project must be refused")

	after, err := env.svc.GetByID(context.Background(), 1, r.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusNew, after.Status, "cross-project call must not mutate anything")
}

// The advertised action list must not offer buttons the caller cannot use: every
// action returned by the detail endpoint has to survive the transition endpoint's
// own permission check.
func TestDetailAdvertisesOnlyPermittedActions(t *testing.T) {
	t.Run("security_ops sees no accept action", func(t *testing.T) {
		env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityOps)
		r := createRiskByRule(t, env.svc)
		require.Equal(t, http.StatusOK,
			env.transition(t, 1, r.ID, map[string]any{"action": StatusActionConfirm, "reason": "triaged"}).Code)

		actions := env.detailActions(t, 1, r.ID)
		assert.Contains(t, actions, StatusActionAssign, "ordinary triage stays offered")
		assert.NotContains(t, actions, StatusActionAccept, "risk:accept is not held")
		assert.NotContains(t, actions, StatusActionFalsePositive, "risk:suppress is not held")

		// Anything still advertised must actually be accepted by the endpoint.
		for _, action := range actions {
			body := map[string]any{"action": action, "reason": "r", "owner": "bob",
				"sla_due_at": "2026-12-31T00:00:00Z"}
			w := env.transition(t, 1, r.ID, body)
			assert.NotEqual(t, http.StatusForbidden, w.Code,
				"advertised action %q must not be refused: %s", action, w.Body.String())
		}
	})

	t.Run("security_admin sees the decision actions", func(t *testing.T) {
		env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityAdmin)
		r := createRiskByRule(t, env.svc)
		require.Equal(t, http.StatusOK,
			env.transition(t, 1, r.ID, map[string]any{"action": StatusActionConfirm, "reason": "triaged"}).Code)

		actions := env.detailActions(t, 1, r.ID)
		assert.Contains(t, actions, StatusActionAccept)
		assert.Contains(t, actions, StatusActionFalsePositive)
	})
}

// detailActions reads available_actions from GET /risks/:id.
func (e *riskHandlerEnv) detailActions(t *testing.T, projectID, riskID uint64) []string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/projects/%d/risks/%d", projectID, riskID), nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	e.engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var envelope struct {
		Data struct {
			AvailableActions []string `json:"available_actions"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	return envelope.Data.AvailableActions
}

// The list endpoint used to accept severity/status/owner/keyword and drop them,
// so the console could only narrow rows already on screen and the reported total
// stayed at the unfiltered count.
func TestListAppliesServerSideFilters(t *testing.T) {
	env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityAdmin)
	seedRisksForFilter(t, env)

	t.Run("severity narrows both items and total", func(t *testing.T) {
		page := env.listRisks(t, "?severity=critical")
		assert.Equal(t, int64(1), page.Total, "total must reflect the filtered set, not the whole project")
		require.Len(t, page.Items, 1)
		assert.Equal(t, SeverityCritical, page.Items[0].Severity)
	})

	t.Run("status filter", func(t *testing.T) {
		page := env.listRisks(t, "?status="+StatusNew)
		assert.Equal(t, int64(2), page.Total)
		for _, item := range page.Items {
			assert.Equal(t, StatusNew, item.Status)
		}
	})

	t.Run("owner filter", func(t *testing.T) {
		page := env.listRisks(t, "?owner=bob")
		assert.Equal(t, int64(1), page.Total)
		assert.Equal(t, "bob", page.Items[0].Owner)
	})

	t.Run("keyword matches the title", func(t *testing.T) {
		page := env.listRisks(t, "?keyword=RDP")
		assert.Equal(t, int64(1), page.Total)
		assert.Contains(t, page.Items[0].Title, "RDP")
	})

	t.Run("asset filter returns only that asset's risks", func(t *testing.T) {
		page := env.listRisks(t, "?asset_id=7")
		assert.Equal(t, int64(2), page.Total)
		for _, item := range page.Items {
			assert.Equal(t, uint64(7), item.AssetID)
		}
	})

	t.Run("combined filters intersect", func(t *testing.T) {
		page := env.listRisks(t, "?severity=high&status="+StatusNew)
		assert.Equal(t, int64(1), page.Total)
	})

	t.Run("no filter returns everything", func(t *testing.T) {
		page := env.listRisks(t, "")
		assert.Equal(t, int64(3), page.Total)
	})
}

// An unknown enum must be a client error, not an empty page that reads as
// "this project has no such risks".
func TestListRejectsUnknownFilterValues(t *testing.T) {
	env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityAdmin)

	for _, query := range []string{"?severity=extreme", "?status=not-a-status", "?asset_id=abc", "?asset_id=0", "?asset_id=-1"} {
		t.Run(query, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/api/v1/projects/1/risks"+query, nil)
			require.NoError(t, err)
			w := httptest.NewRecorder()
			env.engine.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		})
	}
}

func seedRisksForFilter(t *testing.T, env *riskHandlerEnv) {
	t.Helper()
	seed := []struct {
		key, title, severity, owner string
	}{
		{"k1", "RDP 端口对互联网开放", SeverityCritical, "alice"},
		{"k2", "Git 目录可下载", SeverityHigh, "bob"},
		{"k3", "TLS 证书即将过期", SeverityLow, "alice"},
	}
	for i, item := range seed {
		id := uint64(i + 1)
		env.repo.risks[id] = &Risk{
			ID: id, ProjectID: 1, RiskKey: item.key, Title: item.title,
			Severity: item.severity, Status: StatusNew, Owner: item.owner,
		}
	}
	// Move one off StatusNew so the status filter has something to exclude.
	env.repo.risks[3].Status = StatusFixed
	env.repo.risks[1].AssetID = 7
	env.repo.risks[3].AssetID = 7
	env.repo.risks[2].AssetID = 8
}

// listRisks issues GET /risks with the given raw query and decodes the page.
func (e *riskHandlerEnv) listRisks(t *testing.T, rawQuery string) httpx.PageData[response] {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/api/v1/projects/1/risks"+rawQuery, nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	e.engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var envelope struct {
		Data httpx.PageData[response] `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	return envelope.Data
}

// Suppression rules had a service, a matching engine and a table, but no HTTP
// surface — the console's calls 404'd. These cover the new routes, and in
// particular that writes need the dedicated risk:suppress permission.
func TestSuppressionRuleRoutes(t *testing.T) {
	t.Run("read follows risk:read", func(t *testing.T) {
		env := newRiskHandlerEnv(t, asmcasbin.RoleViewer)
		w := env.request(t, http.MethodGet, "/api/v1/projects/1/risk-suppressions", nil)
		assert.Equal(t, http.StatusOK, w.Code, "a viewer holds risk:read: %s", w.Body.String())
	})

	t.Run("create requires risk:suppress", func(t *testing.T) {
		// project_owner holds risk:accept but deliberately not risk:suppress.
		env := newRiskHandlerEnv(t, asmcasbin.RoleProjectOwner)
		require.False(t, env.enforcer.HasPolicy(asmcasbin.RoleProjectOwner, asmcasbin.GlobalDomain, asmcasbin.PermRiskSuppress, "allow"))

		w := env.request(t, http.MethodPost, "/api/v1/projects/1/risk-suppressions", map[string]any{
			"name": "忽略测试环境", "risk_type": TypeHighRiskPort, "reason": "test bed",
		})
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("privileged role creates and lists", func(t *testing.T) {
		env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityAdmin)

		w := env.request(t, http.MethodPost, "/api/v1/projects/1/risk-suppressions", map[string]any{
			"name": "忽略测试环境", "risk_type": TypeHighRiskPort, "rule_id": "RULE-0001",
			"reason": "test bed", "expires_at": "2026-12-31T00:00:00Z",
		})
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

		var created struct {
			Data suppressionRuleResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
		assert.Equal(t, "忽略测试环境", created.Data.Name)
		assert.Equal(t, TypeHighRiskPort, created.Data.RiskType)
		assert.True(t, created.Data.Enabled, "a new rule is active immediately")

		list := env.request(t, http.MethodGet, "/api/v1/projects/1/risk-suppressions", nil)
		require.Equal(t, http.StatusOK, list.Code, list.Body.String())
		var page struct {
			Data httpx.PageData[suppressionRuleResponse] `json:"data"`
		}
		require.NoError(t, json.Unmarshal(list.Body.Bytes(), &page))
		assert.Equal(t, int64(1), page.Data.Total)
	})

	t.Run("disable requires risk:suppress and takes effect", func(t *testing.T) {
		env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityAdmin)
		created := env.request(t, http.MethodPost, "/api/v1/projects/1/risk-suppressions", map[string]any{
			"name": "r", "risk_type": TypeHighRiskPort, "reason": "why",
		})
		require.Equal(t, http.StatusCreated, created.Code)
		var body struct {
			Data suppressionRuleResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(created.Body.Bytes(), &body))

		path := fmt.Sprintf("/api/v1/projects/1/risk-suppressions/%d/enabled", body.Data.ID)
		w := env.request(t, http.MethodPatch, path, map[string]any{"enabled": false})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		list := env.request(t, http.MethodGet, "/api/v1/projects/1/risk-suppressions", nil)
		var page struct {
			Data httpx.PageData[suppressionRuleResponse] `json:"data"`
		}
		require.NoError(t, json.Unmarshal(list.Body.Bytes(), &page))
		require.Len(t, page.Data.Items, 1)
		assert.False(t, page.Data.Items[0].Enabled,
			"a disabled rule must still be listed, otherwise it cannot be re-enabled")
	})

	t.Run("cross-project access is refused", func(t *testing.T) {
		env := newRiskHandlerEnv(t, asmcasbin.RoleSecurityAdmin)
		w := env.request(t, http.MethodGet, "/api/v1/projects/2/risk-suppressions", nil)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// request issues an arbitrary JSON request against the wired engine.
func (e *riskHandlerEnv) request(t *testing.T, method, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, path, reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.engine.ServeHTTP(w, req)
	return w
}
