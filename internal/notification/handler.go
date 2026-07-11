//revive:disable:exported

package notification

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

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
	g := protected.Group("/projects/:project_id/notification-rules")
	g.Use(auth.ProjectIDFromParam("project_id"))
	g.GET("", h.list)
	g.POST("", h.create)
	g.PATCH("/:id/enabled", h.setEnabled)
}

type createRuleRequest struct {
	Name           string          `json:"name"`
	Trigger        string          `json:"trigger"`
	Condition      json.RawMessage `json:"condition"`
	Channel        string          `json:"channel"`
	Recipients     []string        `json:"recipients"`
	ThrottleWindow uint32          `json:"throttle_window"`
}

type setEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

type ruleResponse struct {
	ID             uint64          `json:"id"`
	ProjectID      uint64          `json:"project_id"`
	Name           string          `json:"name"`
	Trigger        string          `json:"trigger"`
	Condition      json.RawMessage `json:"condition,omitempty"`
	Channel        string          `json:"channel"`
	Recipients     []string        `json:"recipients"`
	ThrottleWindow uint32          `json:"throttle_window"`
	Enabled        bool            `json:"enabled"`
	CreatedBy      string          `json:"created_by"`
	UpdatedBy      string          `json:"updated_by"`
}

func (h *Handler) list(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid) {
		return
	}
	rows, err := h.svc.ListRules(c.Request.Context(), pid)
	if err != nil {
		writeErr(c, err)
		return
	}
	items := make([]ruleResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toResponse(row))
	}
	httpx.OK(c, items)
}

func (h *Handler) create(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid) {
		return
	}
	var req createRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid json body")
		return
	}
	rule, err := h.svc.CreateRule(c.Request.Context(), CreateRuleInput{
		ProjectID: pid, Name: req.Name, Trigger: req.Trigger, Condition: req.Condition,
		Channel: req.Channel, Recipients: req.Recipients, ThrottleWindow: req.ThrottleWindow,
		ActorID: c.GetString(auth.CtxUserID),
	})
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.Created(c, toResponse(rule))
}

func (h *Handler) setEnabled(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid) {
		return
	}
	id, ok := parseID(c)
	if !ok {
		return
	}
	var req setEnabledRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid json body")
		return
	}
	if err := h.svc.SetRuleEnabled(c.Request.Context(), pid, id, req.Enabled, c.GetString(auth.CtxUserID)); err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, gin.H{"updated": true})
}

func (h *Handler) projectID(c *gin.Context) (uint64, bool) {
	pid, err := strconv.ParseUint(c.Param("project_id"), 10, 64)
	if err != nil || pid == 0 {
		httpx.BadRequest(c, "invalid project_id")
		return 0, false
	}
	return pid, true
}

func (h *Handler) accessAndPermit(c *gin.Context, pid uint64) bool {
	userID := c.GetString(auth.CtxUserID)
	_, role, err := h.projects.Access(c.Request.Context(), userID, pid)
	switch {
	case err == nil:
	case errors.Is(err, project.ErrNotFound):
		httpx.NotFound(c, httpx.ErrCodeProjectNotFound, "project not found")
		return false
	case errors.Is(err, project.ErrForbidden):
		httpx.Forbidden(c)
		return false
	default:
		httpx.Internal(c)
		return false
	}
	if role != "" && h.enforcer.HasPolicy(role, asmcasbin.GlobalDomain, asmcasbin.PermNotifWrite, "allow") {
		return true
	}
	if ok, err := h.enforcer.Enforce(userID, strconv.FormatUint(pid, 10), asmcasbin.PermNotifWrite, "allow"); err == nil && ok {
		return true
	}
	httpx.Forbidden(c)
	return false
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
		httpx.NotFound(c, "NOTIFICATION_RULE_NOT_FOUND", "notification rule not found")
	case errors.Is(err, ErrInvalidProjectID), errors.Is(err, ErrInvalidActorID), errors.Is(err, ErrInvalidTrigger),
		errors.Is(err, ErrInvalidChannel), errors.Is(err, ErrInvalidName), errors.Is(err, ErrInvalidRecipient),
		errors.Is(err, ErrFieldTooLong):
		httpx.BadRequest(c, err.Error())
	default:
		httpx.Internal(c)
	}
}

func toResponse(rule *Rule) ruleResponse {
	return ruleResponse{
		ID: rule.ID, ProjectID: rule.ProjectID, Name: rule.Name, Trigger: rule.Trigger,
		Condition: rule.Condition, Channel: rule.Channel, Recipients: rule.Recipients,
		ThrottleWindow: rule.ThrottleWindow, Enabled: rule.Enabled,
		CreatedBy: rule.CreatedBy, UpdatedBy: rule.UpdatedBy,
	}
}
