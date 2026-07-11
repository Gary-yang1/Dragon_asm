//revive:disable:exported

package exposure

import (
	"context"
	"errors"
	"strconv"

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
	g := protected.Group("/projects/:project_id/exposures")
	g.Use(auth.ProjectIDFromParam("project_id"))
	g.GET("", h.list)
	g.GET("/:id", h.detail)
}

type response struct {
	ID            uint64   `json:"id"`
	ProjectID     uint64   `json:"project_id"`
	AssetID       uint64   `json:"asset_id"`
	ExposureType  string   `json:"exposure_type"`
	ExposureKey   string   `json:"exposure_key"`
	Name          string   `json:"name"`
	Value         string   `json:"value"`
	Protocol      string   `json:"protocol"`
	Port          uint32   `json:"port"`
	Service       string   `json:"service"`
	Version       string   `json:"version"`
	CPE           string   `json:"cpe"`
	URL           string   `json:"url"`
	Fingerprint   string   `json:"fingerprint"`
	CertSubject   string   `json:"cert_subject"`
	CertIssuer    string   `json:"cert_issuer"`
	CertSerial    string   `json:"cert_serial"`
	CertNotBefore string   `json:"cert_not_before"`
	CertNotAfter  string   `json:"cert_not_after"`
	CertSANs      []string `json:"cert_sans"`
	EvidenceHash  string   `json:"evidence_hash"`
	Source        string   `json:"source"`
	Confidence    uint8    `json:"confidence"`
	FirstSeen     string   `json:"first_seen"`
	LastSeen      string   `json:"last_seen"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
	CreatedBy     string   `json:"created_by"`
	UpdatedBy     string   `json:"updated_by"`
}

func toResponse(e *Exposure) response {
	return response{
		ID:            e.ID,
		ProjectID:     e.ProjectID,
		AssetID:       e.AssetID,
		ExposureType:  e.ExposureType,
		ExposureKey:   e.ExposureKey,
		Name:          e.Name,
		Value:         e.Value,
		Protocol:      e.Protocol,
		Port:          e.Port,
		Service:       e.Service,
		Version:       e.Version,
		CPE:           e.CPE,
		URL:           e.URL,
		Fingerprint:   e.Fingerprint,
		CertSubject:   e.CertSubject,
		CertIssuer:    e.CertIssuer,
		CertSerial:    e.CertSerial,
		CertNotBefore: e.CertNotBefore.UTC().Format(timeRFC3339Millis),
		CertNotAfter:  e.CertNotAfter.UTC().Format(timeRFC3339Millis),
		CertSANs:      e.CertSANs,
		EvidenceHash:  e.EvidenceHash,
		Source:        e.Source,
		Confidence:    e.Confidence,
		FirstSeen:     e.FirstSeen.UTC().Format(timeRFC3339Millis),
		LastSeen:      e.LastSeen.UTC().Format(timeRFC3339Millis),
		CreatedAt:     e.CreatedAt.UTC().Format(timeRFC3339Millis),
		UpdatedAt:     e.UpdatedAt.UTC().Format(timeRFC3339Millis),
		CreatedBy:     e.CreatedBy,
		UpdatedBy:     e.UpdatedBy,
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
	if !h.permit(c, role, pid) {
		return
	}
	pq, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}
	const maxInt32 = 1<<31 - 1
	limit := int32(pq.Limit()) //nolint:gosec // G115: bounded by BindPageQuery.
	offset := pq.Offset()
	if offset > maxInt32 {
		httpx.BadRequest(c, "page_number out of range")
		return
	}
	rows, err := h.svc.List(c.Request.Context(), pid, limit, int32(offset)) //nolint:gosec // G115: guarded above.
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
	for _, e := range rows {
		items = append(items, toResponse(e))
	}
	httpx.OK(c, httpx.PageData[response]{
		Items:      items,
		Total:      total,
		PageSize:   pq.PageSize,
		PageNumber: pq.PageNumber,
	})
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
	if !h.permit(c, role, pid) {
		return
	}
	id, ok := parseID(c)
	if !ok {
		return
	}
	e, err := h.svc.GetByID(c.Request.Context(), pid, id)
	if err != nil {
		writeErr(c, err)
		return
	}
	httpx.OK(c, toResponse(e))
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

func (h *Handler) permit(c *gin.Context, role string, pid uint64) bool {
	if role != "" && h.enforcer.HasPolicy(role, asmcasbin.GlobalDomain, asmcasbin.PermExposureRead, "allow") {
		return true
	}
	userID := c.GetString(auth.CtxUserID)
	if ok, err := h.enforcer.Enforce(userID, strconv.FormatUint(pid, 10), asmcasbin.PermExposureRead, "allow"); err == nil && ok {
		return true
	}
	httpx.Forbidden(c)
	return false
}

func parseProjectID(c *gin.Context) (uint64, bool) {
	raw := c.Param("project_id")
	pid, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || pid == 0 {
		httpx.BadRequest(c, "invalid project_id")
		return 0, false
	}
	return pid, true
}

func parseID(c *gin.Context) (uint64, bool) {
	raw := c.Param("id")
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		httpx.BadRequest(c, "invalid id")
		return 0, false
	}
	return id, true
}

func writeErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.NotFound(c, httpx.ErrCodeNotFound, "exposure not found")
	case errors.Is(err, ErrInvalidProjectID):
		httpx.BadRequest(c, "invalid project_id")
	default:
		httpx.Internal(c)
	}
}
