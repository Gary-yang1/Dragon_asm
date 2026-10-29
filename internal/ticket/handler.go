//revive:disable:exported

package ticket

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

type projectAccess interface {
	Access(ctx context.Context, userID string, projectID uint64) (*project.Project, string, error)
}

type Handler struct {
	svc      *Service
	projects projectAccess
	enforcer *casbin.Enforcer
}

func NewHandler(svc *Service, projects projectAccess, enforcer *casbin.Enforcer) *Handler {
	return &Handler{svc: svc, projects: projects, enforcer: enforcer}
}

func (h *Handler) RegisterRoutes(protected *gin.RouterGroup) {
	g := protected.Group("/projects/:project_id/tickets")
	g.Use(auth.ProjectIDFromParam("project_id"))
	g.GET("", h.list)
	g.POST("", h.create)
	g.GET("/:id", h.detail)
	g.POST("/:id/status-transitions", h.transition)
}

type createRequest struct {
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Assignee         string   `json:"assignee"`
	BusinessUnit     string   `json:"business_unit"`
	Priority         string   `json:"priority"`
	DueAt            string   `json:"due_at"`
	ExternalTicketID string   `json:"external_ticket_id"`
	RiskIDs          []uint64 `json:"risk_ids"`
}

type transitionRequest struct {
	Action           string `json:"action"`
	Assignee         string `json:"assignee"`
	DueAt            string `json:"due_at"`
	Resolution       string `json:"resolution"`
	RetestResult     string `json:"retest_result"`
	Reason           string `json:"reason"`
	ApprovedBy       string `json:"approved_by"`
	ExpiresAt        string `json:"expires_at"`
	ReviewRequiredAt string `json:"review_required_at"`
}

type response struct {
	ID               uint64 `json:"id"`
	ProjectID        uint64 `json:"project_id"`
	Title            string `json:"title"`
	Description      string `json:"description"`
	Assignee         string `json:"assignee"`
	BusinessUnit     string `json:"business_unit"`
	Status           string `json:"status"`
	Priority         string `json:"priority"`
	DueAt            string `json:"due_at"`
	Resolution       string `json:"resolution"`
	RetestResult     string `json:"retest_result"`
	ExternalTicketID string `json:"external_ticket_id"`
	ClosedAt         string `json:"closed_at"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	CreatedBy        string `json:"created_by"`
	UpdatedBy        string `json:"updated_by"`
	// AvailableActions is derived from the transition table so the client need not
	// duplicate it. Advisory only — the transition endpoint re-checks.
	AvailableActions []string `json:"available_actions"`
}

func (h *Handler) create(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok {
		return
	}
	role, permitted := h.accessAndPermit(c, pid, asmcasbin.PermTicketWrite)
	if !permitted {
		return
	}
	var req createRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid json body")
		return
	}
	dueAt, err := parseOptionalTime(req.DueAt)
	if err != nil {
		httpx.BadRequest(c, "invalid due_at")
		return
	}
	t, err := h.svc.Create(c.Request.Context(), CreateInput{
		ProjectID: pid, Title: req.Title, Description: req.Description,
		Assignee: req.Assignee, BusinessUnit: req.BusinessUnit, Priority: req.Priority,
		DueAt: dueAt, ExternalTicketID: req.ExternalTicketID, RiskIDs: req.RiskIDs,
		ActorID: c.GetString(auth.CtxUserID),
	})
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.Created(c, h.withPermittedActions(c, role, pid, toResponse(t)))
}

func (h *Handler) list(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok {
		return
	}
	role, permitted := h.accessAndPermit(c, pid, asmcasbin.PermTicketRead)
	if !permitted {
		return
	}
	pq, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}
	const maxInt32 = 1<<31 - 1
	offset := pq.Offset()
	if offset > maxInt32 {
		httpx.BadRequest(c, "page_number out of range")
		return
	}
	rows, err := h.svc.List(c.Request.Context(), pid, int32(pq.Limit()), int32(offset)) //nolint:gosec // bounds checked.
	if err != nil {
		httpx.InternalError(c, err)
		return
	}
	total, err := h.svc.Count(c.Request.Context(), pid)
	if err != nil {
		httpx.InternalError(c, err)
		return
	}
	items := make([]response, 0, len(rows))
	for _, t := range rows {
		items = append(items, h.withPermittedActions(c, role, pid, toResponse(t)))
	}
	httpx.OK(c, httpx.PageData[response]{Items: items, Total: total, PageSize: pq.PageSize, PageNumber: pq.PageNumber})
}

func (h *Handler) detail(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok {
		return
	}
	role, permitted := h.accessAndPermit(c, pid, asmcasbin.PermTicketRead)
	if !permitted {
		return
	}
	id, ok := parseID(c)
	if !ok {
		return
	}
	t, err := h.svc.GetByID(c.Request.Context(), pid, id)
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, h.withPermittedActions(c, role, pid, toResponse(t)))
}

func (h *Handler) transition(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok {
		return
	}
	role, permitted := h.accessAndPermit(c, pid, asmcasbin.PermTicketWrite)
	if !permitted {
		return
	}
	id, ok := parseID(c)
	if !ok {
		return
	}
	var req transitionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid json body")
		return
	}
	// ticket:write covers ordinary progression. Approving a retest, and any action
	// that reaches into the linked risk, each need a further permission.
	for _, perm := range []string{
		ticketPermissionForAction(req.Action),
		riskPermissionForTicketAction(req.Action),
	} {
		if perm == "" {
			continue
		}
		if !h.rolePermits(c, role, pid, perm) {
			httpx.Forbidden(c)
			return
		}
	}
	dueAt, err := parseOptionalTime(req.DueAt)
	if err != nil {
		httpx.BadRequest(c, "invalid due_at")
		return
	}
	expiresAt, err := parseOptionalTime(req.ExpiresAt)
	if err != nil {
		httpx.BadRequest(c, "invalid expires_at")
		return
	}
	reviewRequiredAt, err := parseOptionalTime(req.ReviewRequiredAt)
	if err != nil {
		httpx.BadRequest(c, "invalid review_required_at")
		return
	}
	t, err := h.svc.Transition(c.Request.Context(), TransitionInput{
		ProjectID: pid, TicketID: id, Action: req.Action, ActorID: c.GetString(auth.CtxUserID),
		Assignee: req.Assignee, DueAt: dueAt, Resolution: req.Resolution, RetestResult: req.RetestResult,
		Reason: req.Reason, ApprovedBy: req.ApprovedBy, ExpiresAt: expiresAt, ReviewRequiredAt: reviewRequiredAt,
	})
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, h.withPermittedActions(c, role, pid, toResponse(t)))
}

func (h *Handler) projectID(c *gin.Context) (uint64, bool) {
	pid, err := strconv.ParseUint(c.Param("project_id"), 10, 64)
	if err != nil || pid == 0 {
		httpx.BadRequest(c, "invalid project_id")
		return 0, false
	}
	return pid, true
}

// accessAndPermit resolves the caller's project access and checks perm. It
// returns the caller's project role so a handler can test a second,
// action-specific permission without re-querying membership.
func (h *Handler) accessAndPermit(c *gin.Context, pid uint64, perm string) (string, bool) {
	userID := c.GetString(auth.CtxUserID)
	_, role, err := h.projects.Access(c.Request.Context(), userID, pid)
	switch {
	case err == nil:
	case errors.Is(err, project.ErrNotFound):
		httpx.NotFound(c, httpx.ErrCodeProjectNotFound, "project not found")
		return "", false
	case errors.Is(err, project.ErrForbidden):
		httpx.Forbidden(c)
		return "", false
	default:
		httpx.Internal(c)
		return "", false
	}
	if h.rolePermits(c, role, pid, perm) {
		return role, true
	}
	httpx.Forbidden(c)
	return "", false
}

// rolePermits checks one permission against an already-resolved role without
// writing a response, so callers can combine several checks.
func (h *Handler) rolePermits(c *gin.Context, role string, pid uint64, perm string) bool {
	if role != "" && h.enforcer.HasPolicy(role, asmcasbin.GlobalDomain, perm, "allow") {
		return true
	}
	userID := c.GetString(auth.CtxUserID)
	ok, err := h.enforcer.Enforce(userID, strconv.FormatUint(pid, 10), perm, "allow")
	return err == nil && ok
}

// withPermittedActions narrows a response's AvailableActions to what this caller
// may actually perform. AvailableActions answers "what does the transition table
// allow"; without this filter the UI would offer an accept_risk button to a
// caller who lacks risk:accept and the click would 403.
func (h *Handler) withPermittedActions(c *gin.Context, role string, pid uint64, resp response) response {
	allowed := make([]string, 0, len(resp.AvailableActions))
	for _, action := range resp.AvailableActions {
		permitted := true
		for _, perm := range []string{ticketPermissionForAction(action), riskPermissionForTicketAction(action)} {
			if perm != "" && !h.rolePermits(c, role, pid, perm) {
				permitted = false
				break
			}
		}
		if permitted {
			allowed = append(allowed, action)
		}
	}
	resp.AvailableActions = allowed
	return resp
}

// riskPermissionForTicketAction returns the risk-domain permission a ticket
// action needs because of what it does to the linked risk, or "" when the action
// stays inside the ticket domain.
//
// Service.Transition drives the linked risk directly (ticket/service.go
// transitionLinkedRisk): accept_risk maps to the risk accept transition and
// false_positive to the risk false-positive transition. Gating these only on
// ticket:write let a developer — who holds ticket:write but only risk:read —
// move a risk into risk_accepted through the ticket endpoint, bypassing the
// risk-domain permissions entirely.
func riskPermissionForTicketAction(action string) string {
	switch action {
	case ActionAcceptRisk:
		return asmcasbin.PermRiskAccept
	case ActionFalsePositive:
		return asmcasbin.PermRiskSuppress
	default:
		return ""
	}
}

// ticketPermissionForAction returns the extra ticket-domain permission an action
// needs on top of ticket:write. Passing a retest closes the ticket on the
// strength of the reviewer's judgement, which is what ticket:approve exists for;
// it was declared but enforced nowhere.
func ticketPermissionForAction(action string) string {
	if action == ActionRetestPass {
		return asmcasbin.PermTicketApprove
	}
	return ""
}

func parseID(c *gin.Context) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		httpx.BadRequest(c, "invalid id")
		return 0, false
	}
	return id, true
}

func writeErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.NotFound(c, "TICKET_NOT_FOUND", "ticket not found")
	case errors.Is(err, ErrInvalidTransition):
		httpx.Conflict(c, httpx.ErrCodeInvalidTransition, "invalid ticket status transition")
	case errors.Is(err, ErrInvalidProjectID), errors.Is(err, ErrInvalidTicketID), errors.Is(err, ErrInvalidRiskID),
		errors.Is(err, ErrInvalidActorID), errors.Is(err, ErrInvalidTitle), errors.Is(err, ErrInvalidAssignee),
		errors.Is(err, ErrInvalidPriority), errors.Is(err, ErrInvalidAction), errors.Is(err, ErrResolutionRequired),
		errors.Is(err, ErrRetestResultRequired), errors.Is(err, ErrDueAtRequired), errors.Is(err, ErrReasonRequired),
		errors.Is(err, ErrApprovedByRequired), errors.Is(err, ErrReviewWindowRequired), errors.Is(err, ErrFieldTooLong):
		httpx.BadRequest(c, err.Error())
	default:
		httpx.Internal(c)
	}
}

func parseOptionalTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, v)
}

func toResponse(t *Ticket) response {
	return response{
		ID: t.ID, ProjectID: t.ProjectID, Title: t.Title, Description: t.Description,
		Assignee: t.Assignee, BusinessUnit: t.BusinessUnit, Status: t.Status, Priority: t.Priority,
		DueAt: formatTime(t.DueAt), Resolution: t.Resolution, RetestResult: t.RetestResult,
		ExternalTicketID: t.ExternalTicketID, ClosedAt: formatTime(t.ClosedAt),
		CreatedAt: formatTime(t.CreatedAt), UpdatedAt: formatTime(t.UpdatedAt),
		CreatedBy: t.CreatedBy, UpdatedBy: t.UpdatedBy,
		AvailableActions: AvailableActions(t.Status),
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() || t.Equal(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)) {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
