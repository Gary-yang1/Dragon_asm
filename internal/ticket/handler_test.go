package ticket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/Gary-yang1/Dragon_asm/internal/project"
	"github.com/Gary-yang1/Dragon_asm/internal/risk"
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

type ticketHandlerEnv struct {
	engine   *gin.Engine
	svc      *Service
	risks    *fakeRiskService
	enforcer *casbin.Enforcer
}

// newTicketHandlerEnv wires the real handler against in-memory stores with the
// production MVP role→permission matrix seeded, so authorization resolves exactly
// as in cmd/api. Test user "1" is a member of project 1 with role.
func newTicketHandlerEnv(t *testing.T, role string) *ticketHandlerEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	repo := newFakeRepo()
	risks := newFakeRiskService()
	svc := NewService(repo, WithRiskService(risks), WithAuditSink(&fakeAudit{}))

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

	return &ticketHandlerEnv{engine: r, svc: svc, risks: risks, enforcer: enforcer}
}

func (e *ticketHandlerEnv) transition(t *testing.T, projectID, ticketID uint64, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/tickets/%d/status-transitions", projectID, ticketID),
		bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.engine.ServeHTTP(w, req)
	return w
}

// seedPendingRetestTicket drives a ticket to pending_retest, the state from which
// accept_risk / false_positive / retest_pass become available.
func (e *ticketHandlerEnv) seedPendingRetestTicket(t *testing.T, riskID uint64) *Ticket {
	t.Helper()
	ctx := context.Background()
	e.risks.risks[riskID] = &risk.Risk{ID: riskID, ProjectID: 1, Status: risk.StatusConfirmed}
	due := time.Now().UTC().Add(24 * time.Hour)

	ticket, err := e.svc.Create(ctx, CreateInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Title: "Fix exposed panel",
		Assignee: "dev1", DueAt: due, RiskIDs: []uint64{riskID}, ActorID: "alice",
	})
	require.NoError(t, err)
	for _, action := range []string{ActionAssign, ActionStart, ActionSubmitRetest} {
		_, err = e.svc.Transition(ctx, TransitionInput{
			ProjectID: 1, TicketID: ticket.ID, Action: action, ActorID: "alice",
			Assignee: "dev1", DueAt: due, RetestResult: "retest requested",
		})
		require.NoError(t, err, "seeding action %s", action)
	}
	return ticket
}

// The escalation this closes: Service.Transition drives the linked risk directly,
// so gating the endpoint only on ticket:write let a developer — who holds
// ticket:write but only risk:read — push a risk to risk_accepted via the ticket
// API, bypassing risk:accept entirely.
func TestTicketAcceptRiskRequiresRiskAcceptPermission(t *testing.T) {
	env := newTicketHandlerEnv(t, asmcasbin.RoleDeveloper)
	require.True(t, env.enforcer.HasPolicy(asmcasbin.RoleDeveloper, asmcasbin.GlobalDomain, asmcasbin.PermTicketWrite, "allow"),
		"precondition: developer holds ticket:write")
	require.False(t, env.enforcer.HasPolicy(asmcasbin.RoleDeveloper, asmcasbin.GlobalDomain, asmcasbin.PermRiskAccept, "allow"),
		"precondition: developer must not hold risk:accept")

	ticket := env.seedPendingRetestTicket(t, 10)
	// Seeding legitimately advanced the linked risk (start → fixing); what matters
	// is that the denied action leaves it exactly where it was.
	statusBefore := env.risks.risks[10].Status

	w := env.transition(t, 1, ticket.ID, map[string]any{
		"action": ActionAcceptRisk, "reason": "accepted by owner", "approved_by": "carol",
		"expires_at":         time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		"review_required_at": time.Now().UTC().Add(15 * 24 * time.Hour).Format(time.RFC3339),
	})
	assert.Equal(t, http.StatusForbidden, w.Code, "accept_risk must require risk:accept: %s", w.Body.String())
	assert.Equal(t, statusBefore, env.risks.risks[10].Status,
		"the linked risk must not move when the ticket action is denied")
	assert.NotEqual(t, risk.StatusRiskAccepted, env.risks.risks[10].Status)
}

func TestTicketFalsePositiveRequiresRiskSuppressPermission(t *testing.T) {
	env := newTicketHandlerEnv(t, asmcasbin.RoleProjectOwner)
	require.False(t, env.enforcer.HasPolicy(asmcasbin.RoleProjectOwner, asmcasbin.GlobalDomain, asmcasbin.PermRiskSuppress, "allow"))

	ticket := env.seedPendingRetestTicket(t, 11)
	statusBefore := env.risks.risks[11].Status

	w := env.transition(t, 1, ticket.ID, map[string]any{
		"action": ActionFalsePositive, "reason": "not reachable", "approved_by": "carol",
		"expires_at":         time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		"review_required_at": time.Now().UTC().Add(15 * 24 * time.Hour).Format(time.RFC3339),
	})
	assert.Equal(t, http.StatusForbidden, w.Code, "false_positive must require risk:suppress: %s", w.Body.String())
	assert.Equal(t, statusBefore, env.risks.risks[11].Status)
	assert.NotEqual(t, risk.StatusFalsePositive, env.risks.risks[11].Status)
}

// Passing a retest closes the ticket on the reviewer's judgement; ticket:approve
// exists for exactly that and was previously enforced nowhere.
func TestTicketRetestPassRequiresTicketApprovePermission(t *testing.T) {
	env := newTicketHandlerEnv(t, asmcasbin.RoleDeveloper)
	require.False(t, env.enforcer.HasPolicy(asmcasbin.RoleDeveloper, asmcasbin.GlobalDomain, asmcasbin.PermTicketApprove, "allow"))

	ticket := env.seedPendingRetestTicket(t, 12)

	// The body is otherwise complete, so a 403 here proves authorization stopped
	// the call rather than field validation.
	w := env.transition(t, 1, ticket.ID, map[string]any{
		"action": ActionRetestPass, "reason": "verified fixed", "retest_result": "pass",
		"resolution": "patched and verified",
	})
	assert.Equal(t, http.StatusForbidden, w.Code, "retest_pass must require ticket:approve: %s", w.Body.String())
}

// A privileged role must still be able to complete the whole flow, otherwise the
// gate would simply have broken the feature.
func TestTicketPrivilegedRoleCompletesRetestAndRiskDecision(t *testing.T) {
	env := newTicketHandlerEnv(t, asmcasbin.RoleSecurityAdmin)
	ticket := env.seedPendingRetestTicket(t, 13)

	w := env.transition(t, 1, ticket.ID, map[string]any{
		"action": ActionAcceptRisk, "reason": "compensating control", "approved_by": "carol",
		"expires_at":         time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		"review_required_at": time.Now().UTC().Add(15 * 24 * time.Hour).Format(time.RFC3339),
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, risk.StatusRiskAccepted, env.risks.risks[13].Status)
}

// Ordinary forward progress must remain available to ticket:write alone.
func TestTicketOrdinaryTransitionStillAllowedWithTicketWrite(t *testing.T) {
	env := newTicketHandlerEnv(t, asmcasbin.RoleDeveloper)
	env.risks.risks[14] = &risk.Risk{ID: 14, ProjectID: 1, Status: risk.StatusConfirmed}
	due := time.Now().UTC().Add(24 * time.Hour)
	ticket, err := env.svc.Create(context.Background(), CreateInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Title: "Fix panel",
		Assignee: "dev1", DueAt: due, RiskIDs: []uint64{14}, ActorID: "alice",
	})
	require.NoError(t, err)

	w := env.transition(t, 1, ticket.ID, map[string]any{
		"action": ActionAssign, "assignee": "dev1", "due_at": due.Format(time.RFC3339),
	})
	assert.Equal(t, http.StatusOK, w.Code, "assign must stay available to ticket:write: %s", w.Body.String())
}

func TestTicketTransitionDeniesNonMemberProject(t *testing.T) {
	env := newTicketHandlerEnv(t, asmcasbin.RoleSecurityAdmin)
	ticket := env.seedPendingRetestTicket(t, 15)

	w := env.transition(t, 2, ticket.ID, map[string]any{"action": ActionRetestPass, "retest_result": "pass"})
	assert.Equal(t, http.StatusForbidden, w.Code)
}
