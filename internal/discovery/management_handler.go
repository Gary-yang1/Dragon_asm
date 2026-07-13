//revive:disable:exported

package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

const (
	errCodeDiscoveryNotFound = "DISCOVERY_RESOURCE_NOT_FOUND"
	errCodeProjectNotActive  = "PROJECT_NOT_ACTIVE"
	errCodeTemplateDisabled  = "DISCOVERY_TEMPLATE_DISABLED"
	errCodeRunConflict       = "DISCOVERY_RUN_CONFLICT"
)

type discoveryProjectAccess interface {
	Access(ctx context.Context, userID string, projectID uint64) (*project.Project, string, error)
}

// ManagementHandler exposes authenticated project-scoped discovery management.
type ManagementHandler struct {
	svc      *Service
	projects discoveryProjectAccess
	enforcer *casbin.Enforcer
}

func NewManagementHandler(svc *Service, projects discoveryProjectAccess, enforcer *casbin.Enforcer) *ManagementHandler {
	return &ManagementHandler{svc: svc, projects: projects, enforcer: enforcer}
}

// RegisterRoutes mounts only on the JWT/password-change protected API group.
func (h *ManagementHandler) RegisterRoutes(protected *gin.RouterGroup) {
	scopes := protected.Group("/projects/:project_id/scopes")
	scopes.Use(auth.ProjectIDFromParam("project_id"))
	scopes.GET("", h.listScopes)
	scopes.POST("", h.createScope)
	scopes.GET("/:scope_id", h.getScope)
	scopes.PATCH("/:scope_id", h.updateScope)
	scopes.POST("/:scope_id/deactivate", h.deactivateScope)

	discovery := protected.Group("/projects/:project_id/discovery")
	discovery.Use(auth.ProjectIDFromParam("project_id"))
	discovery.GET("/templates", h.listTemplates)
	discovery.POST("/templates", h.createTemplate)
	discovery.GET("/templates/:template_id", h.getTemplate)
	discovery.PATCH("/templates/:template_id", h.updateTemplate)
	discovery.PATCH("/templates/:template_id/enabled", h.setTemplateEnabled)
	discovery.DELETE("/templates/:template_id", h.deleteTemplate)
	discovery.POST("/templates/:template_id/runs", h.createRun)
	discovery.GET("/runs", h.listRuns)
	discovery.GET("/runs/:run_id", h.getRun)
	discovery.POST("/runs/:run_id/cancel", h.cancelRun)
}

type scopeTargetRequest struct {
	TargetType string `json:"target_type" binding:"required,oneof=domain ip cidr url"`
	MatchMode  string `json:"match_mode" binding:"required,oneof=include exclude"`
	Value      string `json:"value" binding:"required,max=512"`
}

type createScopeRequest struct {
	Name         string               `json:"name" binding:"required,max=128"`
	Status       string               `json:"status" binding:"omitempty,oneof=active inactive"`
	AuthorizedBy string               `json:"authorized_by" binding:"required,max=64"`
	ValidFrom    time.Time            `json:"valid_from" binding:"required"`
	ValidUntil   time.Time            `json:"valid_until" binding:"required"`
	Targets      []scopeTargetRequest `json:"targets" binding:"required,min=1,max=1000,dive"`
}

type updateScopeRequest struct {
	Name         *string               `json:"name" binding:"omitempty,min=1,max=128"`
	Status       *string               `json:"status" binding:"omitempty,oneof=active inactive"`
	AuthorizedBy *string               `json:"authorized_by" binding:"omitempty,min=1,max=64"`
	ValidFrom    *time.Time            `json:"valid_from"`
	ValidUntil   *time.Time            `json:"valid_until"`
	Targets      *[]scopeTargetRequest `json:"targets" binding:"omitempty,min=1,max=1000,dive"`
}

type templateRequest struct {
	ScopeID        uint64          `json:"scope_id" binding:"required"`
	Name           string          `json:"name" binding:"required,max=128"`
	TaskType       string          `json:"task_type" binding:"required,oneof=dns ct_log port_probe web_probe fingerprint cloud_sync passive_intel import"`
	Config         json.RawMessage `json:"config" binding:"required"`
	Schedule       string          `json:"schedule" binding:"max=255"`
	Enabled        bool            `json:"enabled"`
	TimeoutSeconds int             `json:"timeout_seconds" binding:"required,min=1,max=86400"`
	RateLimit      int             `json:"rate_limit" binding:"required,min=1,max=10000"`
	Concurrency    int             `json:"concurrency" binding:"required,min=1,max=500"`
	RetryLimit     int             `json:"retry_limit" binding:"min=0,max=100"`
}

type updateTemplateRequest struct {
	Name           *string          `json:"name" binding:"omitempty,min=1,max=128"`
	TaskType       *string          `json:"task_type" binding:"omitempty,oneof=dns ct_log port_probe web_probe fingerprint cloud_sync passive_intel import"`
	Config         *json.RawMessage `json:"config"`
	Schedule       *string          `json:"schedule" binding:"omitempty,max=255"`
	TimeoutSeconds *int             `json:"timeout_seconds" binding:"omitempty,min=1,max=86400"`
	RateLimit      *int             `json:"rate_limit" binding:"omitempty,min=1,max=10000"`
	Concurrency    *int             `json:"concurrency" binding:"omitempty,min=1,max=500"`
	RetryLimit     *int             `json:"retry_limit" binding:"omitempty,min=0,max=100"`
}

type enabledRequest struct {
	Enabled *bool `json:"enabled" binding:"required"`
}

type scopeResponse struct {
	ID           uint64           `json:"id"`
	ProjectID    uint64           `json:"project_id"`
	Name         string           `json:"name"`
	Status       string           `json:"status"`
	AuthorizedBy string           `json:"authorized_by"`
	ValidFrom    string           `json:"valid_from"`
	ValidUntil   string           `json:"valid_until"`
	Targets      []targetResponse `json:"targets"`
	CreatedAt    string           `json:"created_at"`
	UpdatedAt    string           `json:"updated_at"`
}

type targetResponse struct {
	ID         uint64 `json:"id"`
	TargetType string `json:"target_type"`
	MatchMode  string `json:"match_mode"`
	Value      string `json:"value"`
}

type templateResponse struct {
	ID             uint64 `json:"id"`
	ProjectID      uint64 `json:"project_id"`
	ScopeID        uint64 `json:"scope_id"`
	Name           string `json:"name"`
	TaskType       string `json:"task_type"`
	Config         any    `json:"config"`
	Schedule       string `json:"schedule"`
	Enabled        bool   `json:"enabled"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	RateLimit      int    `json:"rate_limit"`
	Concurrency    int    `json:"concurrency"`
	RetryLimit     int    `json:"retry_limit"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type runResponse struct {
	ID             uint64 `json:"id"`
	ProjectID      uint64 `json:"project_id"`
	TemplateID     uint64 `json:"template_id"`
	ScopeID        uint64 `json:"scope_id"`
	TaskType       string `json:"task_type"`
	Status         string `json:"status"`
	Progress       int    `json:"progress"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	RateLimit      int    `json:"rate_limit"`
	Concurrency    int    `json:"concurrency"`
	RetryLimit     int    `json:"retry_limit"`
	Attempt        int    `json:"attempt"`
	EngineJobID    string `json:"engine_job_id"`
	DispatchedAt   string `json:"dispatched_at,omitempty"`
	LastCallbackAt string `json:"last_callback_at,omitempty"`
	ResultCount    uint64 `json:"result_count"`
	StartedAt      string `json:"started_at,omitempty"`
	FinishedAt     string `json:"finished_at,omitempty"`
	ErrorSummary   string `json:"error_summary"`
}

func (h *ManagementHandler) listScopes(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermScopeRead)
	if !ok {
		return
	}
	items, err := h.svc.ListScopes(c.Request.Context(), pid)
	if err != nil {
		writeManagementError(c, err)
		return
	}
	if !sortScopes(c, items) {
		return
	}
	out := make([]scopeResponse, 0, len(items))
	for _, item := range items {
		out = append(out, scopeDTO(item))
	}
	writePage(c, out)
}

func (h *ManagementHandler) createScope(c *gin.Context) {
	pid, p, _, ok := h.authorize(c, asmcasbin.PermScopeWrite)
	if !ok {
		return
	}
	var req createScopeRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid scope request")
		return
	}
	targets := make([]ScopeTargetInput, 0, len(req.Targets))
	for _, target := range req.Targets {
		targets = append(targets, ScopeTargetInput(target))
	}
	item, err := h.svc.CreateScope(c.Request.Context(), CreateScopeInput{
		TenantID: p.TenantID, OrgID: p.OrgID, ProjectID: pid, Name: req.Name, Status: req.Status,
		AuthorizedBy: req.AuthorizedBy, ValidFrom: req.ValidFrom, ValidUntil: req.ValidUntil,
		ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c), Targets: targets,
	})
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.Created(c, scopeDTO(item))
}

func (h *ManagementHandler) getScope(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermScopeRead)
	if !ok {
		return
	}
	id, ok := managementID(c, "scope_id")
	if !ok {
		return
	}
	item, err := h.svc.GetScope(c.Request.Context(), pid, id)
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, scopeDTO(item))
}

func (h *ManagementHandler) updateScope(c *gin.Context) {
	pid, p, _, ok := h.authorize(c, asmcasbin.PermScopeWrite)
	if !ok {
		return
	}
	id, ok := managementID(c, "scope_id")
	if !ok {
		return
	}
	var req updateScopeRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid scope request")
		return
	}
	if req.Name == nil && req.Status == nil && req.AuthorizedBy == nil && req.ValidFrom == nil && req.ValidUntil == nil && req.Targets == nil {
		httpx.BadRequest(c, "scope update must contain at least one field")
		return
	}
	var targets *[]ScopeTargetInput
	if req.Targets != nil {
		converted := make([]ScopeTargetInput, 0, len(*req.Targets))
		for _, target := range *req.Targets {
			converted = append(converted, ScopeTargetInput(target))
		}
		targets = &converted
	}
	item, err := h.svc.UpdateScope(c.Request.Context(), UpdateScopeInput{
		ScopeID: id, TenantID: p.TenantID, OrgID: p.OrgID, ProjectID: pid, Name: req.Name,
		AuthorizedBy: req.AuthorizedBy, ValidFrom: req.ValidFrom, ValidUntil: req.ValidUntil,
		Status: req.Status, ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c), Targets: targets,
	})
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, scopeDTO(item))
}

func (h *ManagementHandler) deactivateScope(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermScopeWrite)
	if !ok {
		return
	}
	id, ok := managementID(c, "scope_id")
	if !ok {
		return
	}
	if err := h.svc.DeactivateScope(c.Request.Context(), DeactivateScopeInput{
		ScopeID: id, ProjectID: pid, ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c),
	}); err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *ManagementHandler) listTemplates(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRead)
	if !ok {
		return
	}
	items, err := h.svc.ListTaskTemplates(c.Request.Context(), pid)
	if err != nil {
		writeManagementError(c, err)
		return
	}
	if !sortTemplates(c, items) {
		return
	}
	out := make([]templateResponse, 0, len(items))
	for _, item := range items {
		out = append(out, templateDTO(item))
	}
	writePage(c, out)
}

func (h *ManagementHandler) createTemplate(c *gin.Context) {
	pid, p, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRun)
	if !ok {
		return
	}
	var req templateRequest
	if c.ShouldBindJSON(&req) != nil || !validJSONObject(req.Config) {
		httpx.BadRequest(c, "invalid task template request")
		return
	}
	item, err := h.svc.CreateTaskTemplate(c.Request.Context(), CreateTaskTemplateInput{
		TenantID: p.TenantID, OrgID: p.OrgID, ProjectID: pid, ScopeID: req.ScopeID, Name: req.Name,
		TaskType: req.TaskType, Config: string(req.Config), Schedule: req.Schedule, Enabled: req.Enabled,
		TimeoutSeconds: req.TimeoutSeconds, RateLimit: req.RateLimit, Concurrency: req.Concurrency,
		RetryLimit: req.RetryLimit, ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c),
	})
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.Created(c, templateDTO(item))
}

func (h *ManagementHandler) getTemplate(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRead)
	if !ok {
		return
	}
	id, ok := managementID(c, "template_id")
	if !ok {
		return
	}
	item, err := h.svc.GetTaskTemplate(c.Request.Context(), pid, id)
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, templateDTO(item))
}

func (h *ManagementHandler) updateTemplate(c *gin.Context) {
	pid, p, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRun)
	if !ok {
		return
	}
	id, ok := managementID(c, "template_id")
	if !ok {
		return
	}
	var req updateTemplateRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid task template request")
		return
	}
	if req.Name == nil && req.TaskType == nil && req.Config == nil && req.Schedule == nil && req.TimeoutSeconds == nil && req.RateLimit == nil && req.Concurrency == nil && req.RetryLimit == nil {
		httpx.BadRequest(c, "task template update must contain at least one field")
		return
	}
	var config *string
	if req.Config != nil {
		if !validJSONObject(*req.Config) {
			httpx.BadRequest(c, "invalid task template config")
			return
		}
		value := string(*req.Config)
		config = &value
	}
	item, err := h.svc.UpdateTaskTemplate(c.Request.Context(), UpdateTaskTemplateInput{
		TemplateID: id, TenantID: p.TenantID, OrgID: p.OrgID, ProjectID: pid, Name: req.Name,
		TaskType: req.TaskType, Config: config, Schedule: req.Schedule, TimeoutSeconds: req.TimeoutSeconds,
		RateLimit: req.RateLimit, Concurrency: req.Concurrency, RetryLimit: req.RetryLimit,
		ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c),
	})
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, templateDTO(item))
}

func (h *ManagementHandler) setTemplateEnabled(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRun)
	if !ok {
		return
	}
	id, ok := managementID(c, "template_id")
	if !ok {
		return
	}
	var req enabledRequest
	if c.ShouldBindJSON(&req) != nil || req.Enabled == nil {
		httpx.BadRequest(c, "invalid enabled request")
		return
	}
	item, err := h.svc.SetTaskTemplateEnabled(c.Request.Context(), SetTaskTemplateEnabledInput{
		TemplateID: id, ProjectID: pid, Enabled: *req.Enabled,
		ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c),
	})
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, templateDTO(item))
}

func (h *ManagementHandler) deleteTemplate(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRun)
	if !ok {
		return
	}
	id, ok := managementID(c, "template_id")
	if !ok {
		return
	}
	if err := h.svc.DeleteTaskTemplate(c.Request.Context(), DeleteTaskTemplateInput{
		TemplateID: id, ProjectID: pid, ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c),
	}); err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *ManagementHandler) createRun(c *gin.Context) {
	pid, p, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRun)
	if !ok {
		return
	}
	if !p.IsActive() {
		httpx.Conflict(c, errCodeProjectNotActive, "project is not active")
		return
	}
	templateID, ok := managementID(c, "template_id")
	if !ok {
		return
	}
	item, err := h.svc.CreateAndEnqueueTaskRun(c.Request.Context(), CreateTaskRunInput{
		TemplateID: templateID, ProjectID: pid, ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c),
	})
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.Created(c, runDTO(item))
}

func (h *ManagementHandler) listRuns(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRead)
	if !ok {
		return
	}
	items, err := h.svc.ListTaskRuns(c.Request.Context(), pid)
	if err != nil {
		writeManagementError(c, err)
		return
	}
	if !sortRuns(c, items) {
		return
	}
	out := make([]runResponse, 0, len(items))
	for _, item := range items {
		out = append(out, runDTO(item))
	}
	writePage(c, out)
}

func (h *ManagementHandler) getRun(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRead)
	if !ok {
		return
	}
	id, ok := managementID(c, "run_id")
	if !ok {
		return
	}
	item, err := h.svc.GetTaskRun(c.Request.Context(), pid, id)
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, runDTO(item))
}

func (h *ManagementHandler) cancelRun(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRun)
	if !ok {
		return
	}
	id, ok := managementID(c, "run_id")
	if !ok {
		return
	}
	if err := h.svc.CancelDispatchedTaskRun(c.Request.Context(), UpdateTaskRunStatusInput{
		RunID: id, ProjectID: pid, ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c),
	}); err != nil {
		writeManagementError(c, err)
		return
	}
	item, err := h.svc.GetTaskRun(c.Request.Context(), pid, id)
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, runDTO(item))
}

func (h *ManagementHandler) authorize(c *gin.Context, permission string) (uint64, *project.Project, string, bool) {
	pid, ok := managementID(c, "project_id")
	if !ok {
		return 0, nil, "", false
	}
	if h.projects == nil || h.enforcer == nil {
		httpx.Forbidden(c)
		return 0, nil, "", false
	}
	p, role, err := h.projects.Access(c.Request.Context(), c.GetString(auth.CtxUserID), pid)
	switch {
	case err == nil:
	case errors.Is(err, project.ErrNotFound):
		httpx.NotFound(c, httpx.ErrCodeProjectNotFound, "project not found")
		return 0, nil, "", false
	case errors.Is(err, project.ErrForbidden):
		httpx.Forbidden(c)
		return 0, nil, "", false
	default:
		httpx.Internal(c)
		return 0, nil, "", false
	}
	if role != "" && h.enforcer.HasPolicy(role, asmcasbin.GlobalDomain, permission, "allow") {
		return pid, p, role, true
	}
	allowed, enforceErr := h.enforcer.Enforce(c.GetString(auth.CtxUserID), strconv.FormatUint(pid, 10), permission, "allow")
	if enforceErr != nil || !allowed {
		httpx.Forbidden(c)
		return 0, nil, "", false
	}
	return pid, p, role, true
}

func managementID(c *gin.Context, name string) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param(name), 10, 64)
	if err != nil || id == 0 {
		httpx.BadRequest(c, "invalid "+name)
		return 0, false
	}
	return id, true
}

func managementMeta(c *gin.Context) AuditMeta {
	return AuditMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent(), RequestID: c.GetString(httpx.RequestIDKey)}
}

func writeManagementError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.NotFound(c, errCodeDiscoveryNotFound, "discovery resource not found")
	case errors.Is(err, ErrTemplateDisabled):
		httpx.Conflict(c, errCodeTemplateDisabled, "task template is disabled")
	case errors.Is(err, ErrDispatchEnqueue):
		httpx.Fail(c, http.StatusServiceUnavailable, "DISCOVERY_DISPATCH_UNAVAILABLE", "discovery dispatch is unavailable")
	case errors.Is(err, ErrEngineNotConfigured):
		httpx.Fail(c, http.StatusServiceUnavailable, "DISCOVERY_ENGINE_UNAVAILABLE", "discovery engine is unavailable")
	case errors.Is(err, ErrInvalidScopeAction), errors.Is(err, ErrInvalidTemplateAction),
		errors.Is(err, ErrInvalidRunTransition), errors.Is(err, ErrTaskRunNotDispatchable),
		errors.Is(err, ErrEngineCancel):
		httpx.Conflict(c, errCodeRunConflict, "discovery resource state conflict")
	case errors.Is(err, ErrInvalidProjectID), errors.Is(err, ErrInvalidName), errors.Is(err, ErrInvalidActorID),
		errors.Is(err, ErrInvalidAuthorizedBy), errors.Is(err, ErrInvalidStatus), errors.Is(err, ErrInvalidTaskType),
		errors.Is(err, ErrInvalidTaskStatus), errors.Is(err, ErrInvalidTemplate), errors.Is(err, ErrInvalidTaskSchedule),
		errors.Is(err, ErrInvalidTaskLimits), errors.Is(err, ErrInvalidTaskConfig), errors.Is(err, ErrInvalidTemplateID),
		errors.Is(err, ErrInvalidTaskRunID), errors.Is(err, ErrInvalidTargetType), errors.Is(err, ErrInvalidMatchMode),
		errors.Is(err, ErrInvalidScopeID), errors.Is(err, ErrInvalidTarget), errors.Is(err, ErrTargetTooLong),
		errors.Is(err, ErrMetadataTooLong), errors.Is(err, ErrInvalidTimeRange), errors.Is(err, ErrDangerousTarget),
		errors.Is(err, ErrDuplicateTargets), errors.Is(err, ErrInvalidHost):
		httpx.Unprocessable(c, "invalid discovery request")
	default:
		httpx.Internal(c)
	}
}

func scopeDTO(item *Scope) scopeResponse {
	targets := make([]targetResponse, 0, len(item.Targets))
	for _, target := range item.Targets {
		targets = append(targets, targetResponse{ID: target.ID, TargetType: target.TargetType, MatchMode: target.MatchMode, Value: target.Value})
	}
	return scopeResponse{ID: item.ID, ProjectID: item.ProjectID, Name: item.Name, Status: item.Status,
		AuthorizedBy: item.AuthorizedBy, ValidFrom: managementTime(item.ValidFrom), ValidUntil: managementTime(item.ValidUntil),
		Targets: targets, CreatedAt: managementTime(item.CreatedAt), UpdatedAt: managementTime(item.UpdatedAt)}
}

func templateDTO(item *TaskTemplate) templateResponse {
	var config any = map[string]any{}
	_ = json.Unmarshal([]byte(item.Config), &config)
	return templateResponse{ID: item.ID, ProjectID: item.ProjectID, ScopeID: item.ScopeID, Name: item.Name,
		TaskType: item.TaskType, Config: config, Schedule: item.Schedule, Enabled: item.Enabled,
		TimeoutSeconds: item.TimeoutSeconds, RateLimit: item.RateLimit, Concurrency: item.Concurrency,
		RetryLimit: item.RetryLimit, CreatedAt: managementTime(item.CreatedAt), UpdatedAt: managementTime(item.UpdatedAt)}
}

func runDTO(item *TaskRun) runResponse {
	return runResponse{ID: item.ID, ProjectID: item.ProjectID, TemplateID: item.TemplateID, ScopeID: item.ScopeID,
		TaskType: item.TaskType, Status: item.Status, Progress: item.Progress, TimeoutSeconds: item.TimeoutSeconds,
		RateLimit: item.RateLimit, Concurrency: item.Concurrency, RetryLimit: item.RetryLimit, Attempt: item.Attempt,
		EngineJobID: item.EngineJobID, DispatchedAt: managementTime(item.DispatchedAt), LastCallbackAt: managementTime(item.LastCallbackAt),
		ResultCount: item.ResultCount, StartedAt: managementTime(item.StartedAt), FinishedAt: managementTime(item.FinishedAt),
		ErrorSummary: item.ErrorSummary}
}

func managementTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func validJSONObject(raw json.RawMessage) bool {
	if !json.Valid(raw) {
		return false
	}
	var value map[string]any
	return json.Unmarshal(raw, &value) == nil && value != nil
}

func writePage[T any](c *gin.Context, items []T) {
	pq, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}
	total := len(items)
	start := pq.Offset()
	if start > total {
		start = total
	}
	end := start + pq.Limit()
	if end > total {
		end = total
	}
	httpx.OK(c, httpx.PageData[T]{Items: items[start:end], Total: int64(total), PageSize: pq.PageSize, PageNumber: pq.PageNumber})
}

func sortDirection(c *gin.Context) (bool, bool) {
	direction := strings.ToLower(strings.TrimSpace(c.DefaultQuery("sort_order", "desc")))
	switch direction {
	case "asc":
		return false, true
	case "desc":
		return true, true
	default:
		httpx.BadRequest(c, "sort_order must be asc or desc")
		return false, false
	}
}

func sortScopes(c *gin.Context, items []*Scope) bool {
	field := c.DefaultQuery("sort_by", "id")
	desc, ok := sortDirection(c)
	if !ok {
		return false
	}
	if field != "id" && field != "name" && field != "status" && field != "valid_until" {
		httpx.BadRequest(c, "invalid sort_by")
		return false
	}
	sort.SliceStable(items, func(i, j int) bool {
		less := false
		switch field {
		case "name":
			less = items[i].Name < items[j].Name
		case "status":
			less = items[i].Status < items[j].Status
		case "valid_until":
			less = items[i].ValidUntil.Before(items[j].ValidUntil)
		default:
			less = items[i].ID < items[j].ID
		}
		if desc {
			return !less && !sameScopeSortValue(field, items[i], items[j])
		}
		return less
	})
	return true
}

func sameScopeSortValue(field string, a, b *Scope) bool {
	switch field {
	case "name":
		return a.Name == b.Name
	case "status":
		return a.Status == b.Status
	case "valid_until":
		return a.ValidUntil.Equal(b.ValidUntil)
	default:
		return a.ID == b.ID
	}
}

func sortTemplates(c *gin.Context, items []*TaskTemplate) bool {
	field := c.DefaultQuery("sort_by", "id")
	desc, ok := sortDirection(c)
	if !ok {
		return false
	}
	if field != "id" && field != "name" && field != "task_type" && field != "enabled" {
		httpx.BadRequest(c, "invalid sort_by")
		return false
	}
	sort.SliceStable(items, func(i, j int) bool {
		var cmp int
		switch field {
		case "name":
			cmp = strings.Compare(items[i].Name, items[j].Name)
		case "task_type":
			cmp = strings.Compare(items[i].TaskType, items[j].TaskType)
		case "enabled":
			cmp = boolCompare(items[i].Enabled, items[j].Enabled)
		default:
			cmp = uintCompare(items[i].ID, items[j].ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
	return true
}

func sortRuns(c *gin.Context, items []*TaskRun) bool {
	field := c.DefaultQuery("sort_by", "id")
	desc, ok := sortDirection(c)
	if !ok {
		return false
	}
	if field != "id" && field != "status" && field != "task_type" && field != "started_at" {
		httpx.BadRequest(c, "invalid sort_by")
		return false
	}
	sort.SliceStable(items, func(i, j int) bool {
		var cmp int
		switch field {
		case "status":
			cmp = strings.Compare(items[i].Status, items[j].Status)
		case "task_type":
			cmp = strings.Compare(items[i].TaskType, items[j].TaskType)
		case "started_at":
			cmp = items[i].StartedAt.Compare(items[j].StartedAt)
		default:
			cmp = uintCompare(items[i].ID, items[j].ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
	return true
}

func uintCompare(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func boolCompare(a, b bool) int {
	if a == b {
		return 0
	}
	if !a && b {
		return -1
	}
	return 1
}
