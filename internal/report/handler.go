//revive:disable:exported

package report

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
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
	g := protected.Group("/projects/:project_id/reports")
	g.Use(auth.ProjectIDFromParam("project_id"))
	g.GET("/dashboard", h.dashboard)
	g.GET("/trends", h.trends)
	g.GET("/top", h.top)
	g.GET("/remediation", h.remediation)
	g.GET("/exports", h.listExports)
	g.POST("/exports", h.createExport)
	g.GET("/exports/:id", h.getExport)
	g.GET("/exports/:id/download", h.downloadExport)
}

type createExportRequest struct {
	ReportType string   `json:"report_type"`
	Format     string   `json:"format"`
	Fields     []string `json:"fields"`
	Filters    any      `json:"filters"`
}

type exportResponse struct {
	ID           uint64   `json:"id"`
	ProjectID    uint64   `json:"project_id"`
	ReportType   string   `json:"report_type"`
	Status       string   `json:"status"`
	Format       string   `json:"format"`
	Fields       []string `json:"fields"`
	Redacted     bool     `json:"redacted"`
	RowCount     uint64   `json:"row_count"`
	FileName     string   `json:"file_name,omitempty"`
	ErrorMessage string   `json:"error_message,omitempty"`
	RequestedBy  string   `json:"requested_by"`
	StartedAt    string   `json:"started_at"`
	FinishedAt   string   `json:"finished_at"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

func (h *Handler) dashboard(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid, asmcasbin.PermReportRead) {
		return
	}
	out, err := h.svc.Dashboard(c.Request.Context(), pid)
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, out)
}

func (h *Handler) trends(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid, asmcasbin.PermReportRead) {
		return
	}
	from, _ := time.Parse(time.RFC3339, c.Query("from"))
	to, _ := time.Parse(time.RFC3339, c.Query("to"))
	out, err := h.svc.Trend(c.Request.Context(), pid, from, to)
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, out)
}

func (h *Handler) top(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid, asmcasbin.PermReportRead) {
		return
	}
	limit := int32(10)
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 32); err == nil {
			limit = int32(n)
		}
	}
	out, err := h.svc.Top(c.Request.Context(), pid, c.DefaultQuery("dimension", "asset"), limit)
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, out)
}

func (h *Handler) remediation(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid, asmcasbin.PermReportRead) {
		return
	}
	out, err := h.svc.Remediation(c.Request.Context(), pid)
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, out)
}

func (h *Handler) listExports(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid, asmcasbin.PermReportRead) {
		return
	}
	pq, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}
	offset := pq.Offset()
	if offset > 1<<31-1 {
		httpx.BadRequest(c, "page_number out of range")
		return
	}
	rows, err := h.svc.ListExports(c.Request.Context(), pid, int32(pq.Limit()), int32(offset)) //nolint:gosec // bounded above.
	if err != nil {
		writeErr(c, err)
		return
	}
	total, err := h.svc.CountExports(c.Request.Context(), pid)
	if err != nil {
		writeErr(c, err)
		return
	}
	items := make([]exportResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toExportResponse(row))
	}
	httpx.OK(c, httpx.PageData[exportResponse]{Items: items, Total: total, PageSize: pq.PageSize, PageNumber: pq.PageNumber})
}

func (h *Handler) createExport(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok {
		return
	}
	canRead := h.accessAndPermit(c, pid, asmcasbin.PermReportRead)
	if !canRead {
		return
	}
	canExport := h.hasPerm(c, pid, asmcasbin.PermReportExport)
	var req createExportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid json body")
		return
	}
	filters, err := marshalFilters(req.Filters)
	if err != nil {
		httpx.BadRequest(c, "invalid filters")
		return
	}
	job, err := h.svc.CreateExport(c.Request.Context(), ExportRequest{
		ProjectID: pid, ReportType: req.ReportType, Format: req.Format, Fields: req.Fields,
		Filters: filters, CanExport: canExport, ActorID: c.GetString(auth.CtxUserID),
		RequestID: c.GetString(httpx.RequestIDKey), IP: c.ClientIP(), UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.Created(c, toExportResponse(job))
}

func (h *Handler) getExport(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid, asmcasbin.PermReportRead) {
		return
	}
	id, ok := parseID(c)
	if !ok {
		return
	}
	job, err := h.svc.GetExport(c.Request.Context(), pid, id)
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, toExportResponse(job))
}

func (h *Handler) downloadExport(c *gin.Context) {
	pid, ok := h.projectID(c)
	if !ok || !h.accessAndPermit(c, pid, asmcasbin.PermReportExport) {
		return
	}
	id, ok := parseID(c)
	if !ok {
		return
	}
	job, err := h.svc.GetExport(c.Request.Context(), pid, id)
	if err != nil {
		writeErr(c, err)
		return
	}
	if job.Status != ExportStatusSucceeded || job.FilePath == "" {
		httpx.Fail(c, http.StatusConflict, httpx.ErrCodeConflict, "export is not ready")
		return
	}
	c.FileAttachment(job.FilePath, filepath.Base(job.FilePath))
}

func (h *Handler) projectID(c *gin.Context) (uint64, bool) {
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

func (h *Handler) accessAndPermit(c *gin.Context, pid uint64, perm string) bool {
	if _, _, ok := h.accessRole(c, pid); !ok {
		return false
	}
	if h.hasPerm(c, pid, perm) {
		return true
	}
	httpx.Forbidden(c)
	return false
}

func (h *Handler) hasPerm(c *gin.Context, pid uint64, perm string) bool {
	userID := c.GetString(auth.CtxUserID)
	_, role, ok := h.accessRole(c, pid)
	if !ok {
		return false
	}
	if role != "" && h.enforcer.HasPolicy(role, asmcasbin.GlobalDomain, perm, "allow") {
		return true
	}
	allowed, err := h.enforcer.Enforce(userID, strconv.FormatUint(pid, 10), perm, "allow")
	return err == nil && allowed
}

func (h *Handler) accessRole(c *gin.Context, pid uint64) (*project.Project, string, bool) {
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

func marshalFilters(v any) ([]byte, error) {
	if v == nil {
		return []byte(`{}`), nil
	}
	return json.Marshal(v)
}

func writeErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.NotFound(c, "REPORT_EXPORT_NOT_FOUND", "report export not found")
	case errors.Is(err, ErrInvalidProjectID), errors.Is(err, ErrInvalidActorID),
		errors.Is(err, ErrInvalidReportType), errors.Is(err, ErrInvalidFormat),
		errors.Is(err, ErrInvalidField), errors.Is(err, ErrFieldTooLong):
		httpx.BadRequest(c, err.Error())
	default:
		httpx.Internal(c)
	}
}

func toExportResponse(job *ExportJob) exportResponse {
	return exportResponse{
		ID: job.ID, ProjectID: job.ProjectID, ReportType: job.ReportType, Status: job.Status,
		Format: job.Format, Fields: job.Fields, Redacted: job.Redacted, RowCount: job.RowCount,
		FileName: filepath.Base(job.FilePath), ErrorMessage: job.ErrorMessage, RequestedBy: job.RequestedBy,
		StartedAt: formatTime(job.StartedAt), FinishedAt: formatTime(job.FinishedAt),
		CreatedAt: formatTime(job.CreatedAt), UpdatedAt: formatTime(job.UpdatedAt),
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() || t.Year() <= 1970 {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
