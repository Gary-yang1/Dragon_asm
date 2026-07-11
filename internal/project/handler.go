package project

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

// Handler exposes project workspace operations over the authenticated API.
type Handler struct {
	svc      *Service
	enforcer *casbin.Enforcer
}

// NewHandler constructs a project workspace HTTP handler.
func NewHandler(svc *Service, enforcer *casbin.Enforcer) *Handler {
	return &Handler{svc: svc, enforcer: enforcer}
}

// RegisterRoutes registers project workspace routes on an authenticated group.
func (h *Handler) RegisterRoutes(protected *gin.RouterGroup) {
	protected.GET("/workspace/summary", h.workspaceSummary)

	projects := protected.Group("/projects")
	projects.GET("", h.list)
	projects.POST("", h.create)

	project := protected.Group("/projects/:project_id")
	project.Use(auth.ProjectIDFromParam("project_id"))
	project.GET("", h.detail)
	project.PATCH("", h.update)
	project.POST("/transitions", h.transition)
	project.GET("/onboarding-status", h.onboardingStatus)
	project.GET("/capabilities", h.capabilities)

	project.GET("/subjects", h.listSubjects)
	project.POST("/subjects", h.createSubject)
	project.PATCH("/subjects/:id", h.updateSubject)

	project.GET("/domains", h.listDomains)
	project.POST("/domains", h.createDomain)
	project.PATCH("/domains/:id", h.updateDomain)

	project.GET("/icp-filings", h.listICPs)
	project.POST("/icp-filings", h.createICP)
	project.PATCH("/icp-filings/:id", h.updateICP)
}

func (h *Handler) workspaceSummary(c *gin.Context) {
	summary, err := h.svc.WorkspaceSummary(c.Request.Context(), c.GetString(auth.CtxUserID), handlerMeta(c))
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, summary)
}

type projectResponse struct {
	ID           uint64 `json:"id"`
	ProjectCode  string `json:"project_code"`
	Name         string `json:"name"`
	OwnerUserID  string `json:"owner_user_id"`
	BusinessUnit string `json:"business_unit"`
	Criticality  string `json:"criticality"`
	Status       string `json:"status"`
	Description  string `json:"description"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

func projectDTO(p *Project) projectResponse {
	return projectResponse{ID: p.ID, ProjectCode: p.ProjectCode, Name: p.Name, OwnerUserID: p.Owner,
		BusinessUnit: p.BusinessUnit, Criticality: p.Criticality, Status: p.Status,
		Description: p.Description, CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339Nano), UpdatedAt: p.UpdatedAt.UTC().Format(time.RFC3339Nano)}
}

type createProjectRequest struct {
	ProjectCode  string `json:"project_code" binding:"required,max=64"`
	Name         string `json:"name" binding:"required,max=255"`
	OwnerUserID  string `json:"owner_user_id" binding:"omitempty,max=64"`
	BusinessUnit string `json:"business_unit" binding:"omitempty,max=128"`
	Criticality  string `json:"criticality" binding:"omitempty,oneof=low medium high critical"`
	Description  string `json:"description" binding:"omitempty,max=65535"`
}

type updateProjectRequest struct {
	Name         *string `json:"name" binding:"omitempty,max=255"`
	OwnerUserID  *string `json:"owner_user_id" binding:"omitempty,max=64"`
	BusinessUnit *string `json:"business_unit" binding:"omitempty,max=128"`
	Criticality  *string `json:"criticality" binding:"omitempty,oneof=low medium high critical"`
	Description  *string `json:"description" binding:"omitempty,max=65535"`
}

type transitionRequest struct {
	Status string `json:"status" binding:"required,oneof=active suspended archived"`
	Reason string `json:"reason" binding:"omitempty,max=512"`
}

type subjectRequest struct {
	SubjectName        string     `json:"subject_name" binding:"required,max=255"`
	SubjectType        string     `json:"subject_type" binding:"omitempty,oneof=company government institution individual other"`
	RegistrationCode   string     `json:"registration_code" binding:"omitempty,max=64"`
	CountryCode        string     `json:"country_code" binding:"omitempty,len=2"`
	Region             string     `json:"region" binding:"omitempty,max=128"`
	IsPrimary          bool       `json:"is_primary"`
	VerificationStatus string     `json:"verification_status" binding:"omitempty,oneof=unverified verified mismatch"`
	Source             string     `json:"source" binding:"omitempty,max=64"`
	VerifiedAt         *time.Time `json:"verified_at"`
	EvidenceSummary    string     `json:"evidence_summary" binding:"omitempty,max=1024"`
}

type domainCreateRequest struct {
	Domain          string `json:"domain" binding:"required,max=253"`
	SubjectID       uint64 `json:"subject_id"`
	IsPrimary       bool   `json:"is_primary"`
	OwnershipStatus string `json:"ownership_status" binding:"omitempty,oneof=unverified verified mismatch"`
	Source          string `json:"source" binding:"omitempty,max=64"`
	EvidenceSummary string `json:"evidence_summary" binding:"omitempty,max=1024"`
}

type domainUpdateRequest struct {
	SubjectID       uint64 `json:"subject_id"`
	IsPrimary       bool   `json:"is_primary"`
	OwnershipStatus string `json:"ownership_status" binding:"omitempty,oneof=unverified verified mismatch"`
	Source          string `json:"source" binding:"omitempty,max=64"`
	EvidenceSummary string `json:"evidence_summary" binding:"omitempty,max=1024"`
}

type icpRequest struct {
	SubjectID        uint64     `json:"subject_id" binding:"required"`
	FilingNo         string     `json:"filing_no" binding:"required,max=128"`
	FilingType       string     `json:"filing_type" binding:"omitempty,oneof=filing license"`
	WebsiteName      string     `json:"website_name" binding:"omitempty,max=255"`
	Status           string     `json:"status" binding:"omitempty,oneof=unverified valid invalid cancelled"`
	ApprovedAt       *time.Time `json:"approved_at"`
	Source           string     `json:"source" binding:"omitempty,max=64"`
	VerifiedAt       *time.Time `json:"verified_at"`
	EvidenceSummary  string     `json:"evidence_summary" binding:"omitempty,max=1024"`
	DomainProfileIDs []uint64   `json:"domain_profile_ids" binding:"max=100,dive,required"`
}

func (h *Handler) list(c *gin.Context) {
	pq, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}
	actorID := c.GetString(auth.CtxUserID)
	global, err := h.svc.HasGlobalPermission(c.Request.Context(), actorID, asmcasbin.PermProjectRead)
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	const maxInt32 = 1<<31 - 1
	limit := int32(pq.Limit()) //nolint:gosec // BindPageQuery caps page size below MaxInt32.
	offset := pq.Offset()
	if offset > maxInt32 {
		httpx.BadRequest(c, "page_number out of range")
		return
	}
	list, err := h.svc.ListProjects(c.Request.Context(), actorID, global, limit, int32(offset), handlerMeta(c)) //nolint:gosec // guarded above.
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	items := make([]projectResponse, 0, len(list.Items))
	for _, p := range list.Items {
		items = append(items, projectDTO(p))
	}
	httpx.OK(c, httpx.PageData[projectResponse]{Items: items, Total: list.Total, PageSize: pq.PageSize, PageNumber: pq.PageNumber})
}

func (h *Handler) create(c *gin.Context) {
	actorID := c.GetString(auth.CtxUserID)
	allowed, err := h.svc.HasGlobalPermission(c.Request.Context(), actorID, asmcasbin.PermProjectCreate)
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	if !allowed {
		httpx.Forbidden(c)
		return
	}
	var req createProjectRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid project request")
		return
	}
	p, err := h.svc.CreateProject(c.Request.Context(), CreateProjectInput{ProjectCode: req.ProjectCode, Name: req.Name,
		OwnerUserID: req.OwnerUserID, BusinessUnit: req.BusinessUnit, Criticality: req.Criticality,
		Description: req.Description, ActorID: actorID, Meta: handlerMeta(c)})
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.Created(c, projectDTO(p))
}

func (h *Handler) detail(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectRead)
	if !ok {
		return
	}
	httpx.OK(c, projectDTO(p))
}

func (h *Handler) update(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectWrite)
	if !ok {
		return
	}
	var req updateProjectRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid project request")
		return
	}
	updated, err := h.svc.UpdateProject(c.Request.Context(), UpdateProjectInput{ProjectID: p.ID, Name: req.Name,
		OwnerUserID: req.OwnerUserID, BusinessUnit: req.BusinessUnit, Criticality: req.Criticality,
		Description: req.Description, ActorID: c.GetString(auth.CtxUserID), Meta: handlerMeta(c)})
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, projectDTO(updated))
}

func (h *Handler) transition(c *gin.Context) {
	pid, ok := parseUintParam(c, "project_id")
	if !ok {
		return
	}
	var req transitionRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid transition request")
		return
	}
	permission := asmcasbin.PermProjectWrite
	if req.Status == StatusArchived {
		permission = asmcasbin.PermProjectArchive
	}
	if _, _, ok := h.accessID(c, pid, permission); !ok {
		return
	}
	p, err := h.svc.TransitionProject(c.Request.Context(), TransitionProjectInput{ProjectID: pid, Status: req.Status,
		Reason: req.Reason, ActorID: c.GetString(auth.CtxUserID), Meta: handlerMeta(c)})
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, projectDTO(p))
}

func (h *Handler) onboardingStatus(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectRead)
	if !ok {
		return
	}
	status, err := h.svc.OnboardingStatus(c.Request.Context(), p.ID)
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, status)
}

func (h *Handler) capabilities(c *gin.Context) {
	pid, ok := parseUintParam(c, "project_id")
	if !ok {
		return
	}
	capabilities, err := h.svc.Capabilities(c.Request.Context(), c.GetString(auth.CtxUserID), pid)
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, capabilities)
}

func (h *Handler) listSubjects(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectRead)
	if !ok {
		return
	}
	items, err := h.svc.ListSubjects(c.Request.Context(), p.ID)
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, gin.H{"items": items})
}

func (h *Handler) createSubject(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectWrite)
	if !ok {
		return
	}
	var req subjectRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid subject request")
		return
	}
	item, err := h.svc.CreateSubject(c.Request.Context(), subjectInput(p.ID, 0, c.GetString(auth.CtxUserID), req, handlerMeta(c)))
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.Created(c, item)
}

func (h *Handler) updateSubject(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectWrite)
	if !ok {
		return
	}
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	var req subjectRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid subject request")
		return
	}
	item, err := h.svc.UpdateSubject(c.Request.Context(), subjectInput(p.ID, id, c.GetString(auth.CtxUserID), req, handlerMeta(c)))
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, item)
}

func subjectInput(pid, id uint64, actor string, req subjectRequest, meta AuditMeta) SubjectInput {
	return SubjectInput{ProjectID: pid, SubjectID: id, SubjectName: req.SubjectName, SubjectType: req.SubjectType,
		RegistrationCode: req.RegistrationCode, CountryCode: req.CountryCode, Region: req.Region,
		IsPrimary: req.IsPrimary, VerificationStatus: req.VerificationStatus, Source: req.Source,
		VerifiedAt: req.VerifiedAt, EvidenceSummary: req.EvidenceSummary, ActorID: actor, Meta: meta}
}

func (h *Handler) listDomains(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectRead)
	if !ok {
		return
	}
	items, err := h.svc.ListDomains(c.Request.Context(), p.ID)
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, gin.H{"items": items})
}

func (h *Handler) createDomain(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectWrite)
	if !ok {
		return
	}
	var req domainCreateRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid domain request")
		return
	}
	item, err := h.svc.CreateDomain(c.Request.Context(), DomainInput{ProjectID: p.ID, Domain: req.Domain, SubjectID: req.SubjectID,
		IsPrimary: req.IsPrimary, OwnershipStatus: req.OwnershipStatus, Source: req.Source,
		EvidenceSummary: req.EvidenceSummary, ActorID: c.GetString(auth.CtxUserID), Meta: handlerMeta(c)})
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.Created(c, item)
}

func (h *Handler) updateDomain(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectWrite)
	if !ok {
		return
	}
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	var req domainUpdateRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid domain request")
		return
	}
	item, err := h.svc.UpdateDomain(c.Request.Context(), DomainInput{ProjectID: p.ID, DomainProfileID: id, SubjectID: req.SubjectID,
		IsPrimary: req.IsPrimary, OwnershipStatus: req.OwnershipStatus, Source: req.Source,
		EvidenceSummary: req.EvidenceSummary, ActorID: c.GetString(auth.CtxUserID), Meta: handlerMeta(c)})
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, item)
}

func (h *Handler) listICPs(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectRead)
	if !ok {
		return
	}
	items, err := h.svc.ListICPs(c.Request.Context(), p.ID)
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, gin.H{"items": items})
}

func (h *Handler) createICP(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectWrite)
	if !ok {
		return
	}
	var req icpRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid ICP request")
		return
	}
	item, err := h.svc.CreateICP(c.Request.Context(), icpInput(p.ID, 0, c.GetString(auth.CtxUserID), req, handlerMeta(c)))
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.Created(c, item)
}

func (h *Handler) updateICP(c *gin.Context) {
	p, _, ok := h.access(c, asmcasbin.PermProjectWrite)
	if !ok {
		return
	}
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	var req icpRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid ICP request")
		return
	}
	item, err := h.svc.UpdateICP(c.Request.Context(), icpInput(p.ID, id, c.GetString(auth.CtxUserID), req, handlerMeta(c)))
	if err != nil {
		writeProjectErr(c, err)
		return
	}
	httpx.OK(c, item)
}

func icpInput(pid, id uint64, actor string, req icpRequest, meta AuditMeta) ICPInput {
	return ICPInput{ProjectID: pid, FilingID: id, SubjectID: req.SubjectID, FilingNo: req.FilingNo,
		FilingType: req.FilingType, WebsiteName: req.WebsiteName, Status: req.Status, ApprovedAt: req.ApprovedAt,
		Source: req.Source, VerifiedAt: req.VerifiedAt, EvidenceSummary: req.EvidenceSummary,
		DomainProfileIDs: req.DomainProfileIDs, ActorID: actor, Meta: meta}
}

func (h *Handler) access(c *gin.Context, permission string) (*Project, string, bool) {
	pid, ok := parseUintParam(c, "project_id")
	if !ok {
		return nil, "", false
	}
	return h.accessID(c, pid, permission)
}

func (h *Handler) accessID(c *gin.Context, pid uint64, permission string) (*Project, string, bool) {
	actorID := c.GetString(auth.CtxUserID)
	p, role, err := h.svc.Access(c.Request.Context(), actorID, pid)
	if err != nil {
		writeProjectErr(c, err)
		return nil, "", false
	}
	if role != "" && asmcasbin.RoleHasPerm(role, permission) {
		return p, role, true
	}
	if h.explicitPermit(actorID, strconv.FormatUint(pid, 10), permission) {
		return p, role, true
	}
	httpx.Forbidden(c)
	return nil, "", false
}

func (h *Handler) explicitPermit(actorID, domain, permission string) bool {
	ok, err := h.enforcer.Enforce(actorID, domain, permission, "allow")
	return err == nil && ok
}

func parseUintParam(c *gin.Context, name string) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param(name), 10, 64)
	if err != nil || id == 0 {
		httpx.BadRequest(c, "invalid "+name)
		return 0, false
	}
	return id, true
}

func handlerMeta(c *gin.Context) AuditMeta {
	return AuditMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent(), RequestID: c.GetString(httpx.RequestIDKey)}
}

func writeProjectErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.NotFound(c, httpx.ErrCodeProjectNotFound, "project resource not found")
	case errors.Is(err, ErrForbidden):
		httpx.Forbidden(c)
	case errors.Is(err, ErrConflict):
		httpx.Conflict(c, httpx.ErrCodeProjectCodeConflict, "project resource already exists")
	case errors.Is(err, ErrNotReady):
		httpx.Fail(c, http.StatusUnprocessableEntity, httpx.ErrCodeProjectNotReady, "project onboarding is incomplete")
	case errors.Is(err, ErrInvalidRootDomain):
		httpx.Fail(c, http.StatusUnprocessableEntity, httpx.ErrCodeInvalidRootDomain, "domain must be a registrable root domain")
	case errors.Is(err, ErrInvalidStatus):
		httpx.Fail(c, http.StatusConflict, httpx.ErrCodeInvalidTransition, "invalid project state transition")
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrInvalidProfile), errors.Is(err, ErrCrossTenantOwner), errors.Is(err, ErrInvalidActor):
		httpx.Unprocessable(c, err.Error())
	default:
		httpx.Internal(c)
	}
}
