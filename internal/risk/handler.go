//revive:disable:exported

package risk

import (
	"context"
	"encoding/json"
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

const timeRFC3339Millis = "2006-01-02T15:04:05.000Z07:00"

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
	g := protected.Group("/projects/:project_id/risks")
	g.Use(auth.ProjectIDFromParam("project_id"))
	g.GET("", h.list)
	g.GET("/:id", h.detail)
	g.POST("/:id/status-transitions", h.transitionStatus)

	sla := protected.Group("/projects/:project_id/sla-policies")
	sla.Use(auth.ProjectIDFromParam("project_id"))
	sla.GET("", h.listSLAPolicies)
	sla.PUT("", h.upsertSLAPolicy)
}

type response struct {
	ID                uint64          `json:"id"`
	ProjectID         uint64          `json:"project_id"`
	AssetID           uint64          `json:"asset_id"`
	ExposureID        uint64          `json:"exposure_id,omitempty"`
	VulnDefinitionID  uint64          `json:"vuln_definition_id,omitempty"`
	RiskKey           string          `json:"risk_key"`
	RiskType          string          `json:"risk_type"`
	Title             string          `json:"title"`
	Severity          string          `json:"severity"`
	Score             uint8           `json:"score"`
	ScoreLevel        string          `json:"score_level"`
	ScoreModelVersion string          `json:"score_model_version"`
	ScoreFactors      json.RawMessage `json:"score_factors,omitempty"`
	ScoredAt          string          `json:"scored_at"`
	RuleID            string          `json:"rule_id"`
	Source            string          `json:"source"`
	EvidenceSummary   string          `json:"evidence_summary"`
	EvidenceRef       string          `json:"evidence_ref"`
	Status            string          `json:"status"`
	Owner             string          `json:"owner"`
	BusinessUnit      string          `json:"business_unit"`
	SLADueAt          string          `json:"sla_due_at"`
	Suppressed        bool            `json:"suppressed"`
	SuppressionRuleID uint64          `json:"suppression_rule_id,omitempty"`
	SuppressedUntil   string          `json:"suppressed_until"`
	FirstSeen         string          `json:"first_seen"`
	LastSeen          string          `json:"last_seen"`
	ConfirmedAt       string          `json:"confirmed_at"`
	FixedAt           string          `json:"fixed_at"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
	CreatedBy         string          `json:"created_by"`
	UpdatedBy         string          `json:"updated_by"`
}

type transitionRequest struct {
	Action           string `json:"action"`
	Reason           string `json:"reason"`
	ApprovedBy       string `json:"approved_by"`
	ExpiresAt        string `json:"expires_at"`
	ReviewRequiredAt string `json:"review_required_at"`
	Owner            string `json:"owner"`
	SLADueAt         string `json:"sla_due_at"`
}

type slaPolicyRequest struct {
	Severity        string `json:"severity"`
	BusinessUnit    string `json:"business_unit"`
	ResponseHours   uint32 `json:"response_hours"`
	ResolutionHours uint32 `json:"resolution_hours"`
}

type slaPolicyResponse struct {
	ID              uint64 `json:"id"`
	ProjectID       uint64 `json:"project_id"`
	Severity        string `json:"severity"`
	BusinessUnit    string `json:"business_unit"`
	ResponseHours   uint32 `json:"response_hours"`
	ResolutionHours uint32 `json:"resolution_hours"`
	Enabled         bool   `json:"enabled"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	CreatedBy       string `json:"created_by"`
	UpdatedBy       string `json:"updated_by"`
}

func toResponse(r *Risk) response {
	return response{
		ID: r.ID, ProjectID: r.ProjectID, AssetID: r.AssetID, ExposureID: r.ExposureID,
		VulnDefinitionID: r.VulnDefinitionID, RiskKey: r.RiskKey, RiskType: r.RiskType,
		Title: r.Title, Severity: r.Severity, Score: r.Score, ScoreLevel: r.ScoreLevel,
		ScoreModelVersion: r.ScoreModelVersion, ScoreFactors: r.ScoreFactors, ScoredAt: formatTime(r.ScoredAt),
		RuleID: r.RuleID, Source: r.Source,
		EvidenceSummary: r.EvidenceSummary, EvidenceRef: r.EvidenceRef, Status: r.Status,
		Owner: r.Owner, BusinessUnit: r.BusinessUnit,
		SLADueAt: formatTime(r.SLADueAt), Suppressed: r.Suppressed,
		SuppressionRuleID: r.SuppressionRuleID, SuppressedUntil: formatTime(r.SuppressedUntil),
		FirstSeen: formatTime(r.FirstSeen), LastSeen: formatTime(r.LastSeen),
		ConfirmedAt: formatTime(r.ConfirmedAt), FixedAt: formatTime(r.FixedAt),
		CreatedAt: formatTime(r.CreatedAt), UpdatedAt: formatTime(r.UpdatedAt),
		CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy,
	}
}

func (h *Handler) list(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermRiskRead) {
		return
	}
	pq, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}
	const maxInt32 = 1<<31 - 1
	limit := int32(pq.Limit()) //nolint:gosec // bounded by BindPageQuery.
	offset := pq.Offset()
	if offset > maxInt32 {
		httpx.BadRequest(c, "page_number out of range")
		return
	}
	rows, err := h.svc.List(c.Request.Context(), pid, limit, int32(offset)) //nolint:gosec // guarded above.
	if err != nil {
		httpx.Internal(c)
		return
	}
	total, err := h.svc.Count(c.Request.Context(), pid)
	if err != nil {
		httpx.Internal(c)
		return
	}
	items := make([]response, 0, len(rows))
	for _, r := range rows {
		items = append(items, toResponse(r))
	}
	httpx.OK(c, httpx.PageData[response]{Items: items, Total: total, PageSize: pq.PageSize, PageNumber: pq.PageNumber})
}

func (h *Handler) detail(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermRiskRead) {
		return
	}
	id, ok := parseID(c)
	if !ok {
		return
	}
	r, err := h.svc.GetByID(c.Request.Context(), pid, id)
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, toResponse(r))
}

func (h *Handler) listSLAPolicies(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermRiskRead) {
		return
	}
	rows, err := h.svc.ListSLAPolicies(c.Request.Context(), pid)
	if err != nil {
		writeErr(c, err)
		return
	}
	items := make([]slaPolicyResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toSLAPolicyResponse(row))
	}
	httpx.OK(c, items)
}

func (h *Handler) upsertSLAPolicy(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermRiskWrite) {
		return
	}
	var req slaPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid json body")
		return
	}
	err := h.svc.UpsertSLAPolicy(c.Request.Context(), UpsertSLAPolicyInput{
		ProjectID: pid, Severity: req.Severity, BusinessUnit: req.BusinessUnit,
		ResponseHours: req.ResponseHours, ResolutionHours: req.ResolutionHours,
		ActorID: c.GetString(auth.CtxUserID),
	})
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, gin.H{"updated": true})
}

func (h *Handler) transitionStatus(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermRiskWrite) {
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
	var slaDueAt time.Time
	if req.SLADueAt != "" {
		var err error
		slaDueAt, err = parseRequestTime(req.SLADueAt)
		if err != nil {
			httpx.BadRequest(c, "invalid sla_due_at")
			return
		}
	}
	var expiresAt time.Time
	if req.ExpiresAt != "" {
		var err error
		expiresAt, err = parseRequestTime(req.ExpiresAt)
		if err != nil {
			httpx.BadRequest(c, "invalid expires_at")
			return
		}
	}
	var reviewRequiredAt time.Time
	if req.ReviewRequiredAt != "" {
		var err error
		reviewRequiredAt, err = parseRequestTime(req.ReviewRequiredAt)
		if err != nil {
			httpx.BadRequest(c, "invalid review_required_at")
			return
		}
	}
	r, err := h.svc.TransitionStatus(c.Request.Context(), StatusTransitionInput{
		ProjectID: pid, RiskID: id, Action: req.Action, ActorID: c.GetString(auth.CtxUserID),
		Reason: req.Reason, ApprovedBy: req.ApprovedBy, ExpiresAt: expiresAt, ReviewRequiredAt: reviewRequiredAt,
		Owner: req.Owner, SLADueAt: slaDueAt,
		Meta: AuditMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent(), RequestID: c.GetString(httpx.RequestIDKey)},
	})
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, toResponse(r))
}

func (h *Handler) access(c *gin.Context, pid uint64) (*project.Project, string, bool) {
	userID := c.GetString(auth.CtxUserID)
	p, role, err := h.projects.Access(c.Request.Context(), userID, pid)
	switch {
	case err == nil:
		return p, role, true
	case errors.Is(err, project.ErrNotFound):
		httpx.NotFound(c, httpx.ErrCodeProjectNotFound, "project not found")
	case errors.Is(err, project.ErrForbidden):
		httpx.Forbidden(c)
	default:
		httpx.Internal(c)
	}
	return nil, "", false
}

func (h *Handler) permit(c *gin.Context, role string, pid uint64, perm string) bool {
	if role != "" && h.enforcer.HasPolicy(role, asmcasbin.GlobalDomain, perm, "allow") {
		return true
	}
	userID := c.GetString(auth.CtxUserID)
	if ok, err := h.enforcer.Enforce(userID, strconv.FormatUint(pid, 10), perm, "allow"); err == nil && ok {
		return true
	}
	httpx.Forbidden(c)
	return false
}

func parseProjectID(c *gin.Context) (uint64, bool) {
	pid, err := strconv.ParseUint(c.Param("project_id"), 10, 64)
	if err != nil || pid == 0 {
		httpx.BadRequest(c, "invalid project_id")
		return 0, false
	}
	return pid, true
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
		httpx.NotFound(c, httpx.ErrCodeRiskNotFound, "risk not found")
	case errors.Is(err, ErrInvalidProjectID):
		httpx.BadRequest(c, "invalid project_id")
	case errors.Is(err, ErrInvalidStatusTransition):
		httpx.Conflict(c, httpx.ErrCodeInvalidTransition, "invalid risk status transition")
	case errors.Is(err, ErrInvalidStatusAction), errors.Is(err, ErrReasonRequired), errors.Is(err, ErrOwnerRequired), errors.Is(err, ErrSLARequired), errors.Is(err, ErrApprovedByRequired), errors.Is(err, ErrReviewRequiredAtMissing), errors.Is(err, ErrInvalidSeverity), errors.Is(err, ErrInvalidSLAHours):
		httpx.BadRequest(c, err.Error())
	default:
		httpx.Internal(c)
	}
}

func parseRequestTime(v string) (time.Time, error) {
	return time.Parse(time.RFC3339, v)
}

func toSLAPolicyResponse(p *SLAPolicy) slaPolicyResponse {
	return slaPolicyResponse{
		ID: p.ID, ProjectID: p.ProjectID, Severity: p.Severity, BusinessUnit: p.BusinessUnit,
		ResponseHours: p.ResponseHours, ResolutionHours: p.ResolutionHours, Enabled: p.Enabled,
		CreatedAt: formatTime(p.CreatedAt), UpdatedAt: formatTime(p.UpdatedAt),
		CreatedBy: p.CreatedBy, UpdatedBy: p.UpdatedBy,
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeRFC3339Millis)
}
