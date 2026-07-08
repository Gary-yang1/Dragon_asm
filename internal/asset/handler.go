// Package asset's handler adapts the asset Service to Gin HTTP routes. Every
// route is project-scoped and enforces two independent authorization layers:
//
//  1. The project access boundary (project.Service.Access): may the user reach
//     this project at all, and what is their membership role there? Unknown
//     projects yield 404; non-members yield 403. Cross-project admin roles reach
//     a project via the explicit project:access Casbin permission (role == "").
//  2. The action permission (permit), via either of two paths: the user's
//     membership role carries asset:read/asset:write in the seeded matrix, OR the
//     user is granted the permission directly via Casbin (global roles assigned
//     through a grouping that the matrix resolves, or a direct user policy).
//
// Project membership alone never grants read or write — the role must also carry
// the permission in the seeded MVP matrix (or an explicit grant must exist).
// Mutating operations (import/update) run the asset change and its audit event
// in one transaction owned by the Service, so a committed change never exists
// without its audit record.
package asset

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

// timeRFC3339Millis is the canonical timestamp format for API responses.
const timeRFC3339Millis = "2006-01-02T15:04:05.000Z07:00"

// projectAccess is the project access boundary the handler enforces before any
// asset read/write. *project.Service satisfies it.
type projectAccess interface {
	Access(ctx context.Context, userID string, projectID uint64) (*project.Project, string, error)
}

// Handler adapts the asset Service to HTTP. It owns no business rules beyond
// request binding, the two-layer authorization, and logging service errors.
type Handler struct {
	svc      *Service
	projects projectAccess
	enforcer *casbin.Enforcer
	logger   *slog.Logger // optional; logs service (tx/audit) failures so they are not silent
}

// NewHandler builds an asset HTTP handler. projects enforces the project access
// boundary and resolves the membership role; enforcer enforces asset:read/
// asset:write against the seeded role→permission matrix; logger may be nil.
func NewHandler(svc *Service, projects *project.Service, enforcer *casbin.Enforcer, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, projects: projects, enforcer: enforcer, logger: logger}
}

// RegisterRoutes mounts the asset endpoints on the protected (authenticated)
// group. Every route carries :project_id, which ProjectIDFromParam stores in the
// context for the authorization layers to read.
func (h *Handler) RegisterRoutes(protected *gin.RouterGroup) {
	g := protected.Group("/projects/:project_id/assets")
	g.Use(auth.ProjectIDFromParam("project_id"))

	g.GET("", h.list)
	g.GET("/:id", h.detail)
	g.POST("/import", h.importAssets)
	g.PATCH("/:id", h.update)

	// Relations sub-resource: directed edges scoped to one asset (:id is the
	// from-asset on POST). Both routes reuse the project access + action permit.
	g.GET("/:id/relations", h.listRelations)
	g.POST("/:id/relations", h.createRelation)
}

// assetResponse is the external representation of an Asset.
type assetResponse struct {
	ID           uint64 `json:"id"`
	ProjectID    uint64 `json:"project_id"`
	AssetType    string `json:"asset_type"`
	AssetKey     string `json:"asset_key"`
	DisplayName  string `json:"display_name"`
	Value        string `json:"value"`
	Source       string `json:"source"`
	Owner        string `json:"owner"`
	BusinessUnit string `json:"business_unit"`
	Confidence   uint8  `json:"confidence"`
	Status       string `json:"status"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	CreatedBy    string `json:"created_by"`
	UpdatedBy    string `json:"updated_by"`
}

func toResponse(a *Asset) assetResponse {
	return assetResponse{
		ID:           a.ID,
		ProjectID:    a.ProjectID,
		AssetType:    a.AssetType,
		AssetKey:     a.AssetKey,
		DisplayName:  a.DisplayName,
		Value:        a.Value,
		Source:       a.Source,
		Owner:        a.Owner,
		BusinessUnit: a.BusinessUnit,
		Confidence:   a.Confidence,
		Status:       a.Status,
		FirstSeen:    a.FirstSeen.UTC().Format(timeRFC3339Millis),
		LastSeen:     a.LastSeen.UTC().Format(timeRFC3339Millis),
		CreatedAt:    a.CreatedAt.UTC().Format(timeRFC3339Millis),
		UpdatedAt:    a.UpdatedAt.UTC().Format(timeRFC3339Millis),
		CreatedBy:    a.CreatedBy,
		UpdatedBy:    a.UpdatedBy,
	}
}

// importRowInput is one row of an import request body.
type importRowInput struct {
	AssetType    string `json:"asset_type" binding:"required"`
	Value        string `json:"value" binding:"required"`
	DisplayName  string `json:"display_name"`
	Source       string `json:"source"`
	Owner        string `json:"owner"`
	BusinessUnit string `json:"business_unit"`
	Confidence   uint8  `json:"confidence"`
	Status       string `json:"status"`
}

type importRequest struct {
	Rows []importRowInput `json:"rows" binding:"required,dive"`
}

// updateRequest is a partial edit. Pointer fields distinguish "omitted" (nil)
// from "set to empty string" (&""). Its layout mirrors UpdateFields so it can be
// converted directly.
type updateRequest struct {
	DisplayName  *string `json:"display_name"`
	Source       *string `json:"source"`
	Owner        *string `json:"owner"`
	BusinessUnit *string `json:"business_unit"`
	Status       *string `json:"status"`
}

// auditMetaFromContext builds the request-scoped audit metadata. It carries no
// secrets and no actor (the actor is supplied separately to the service).
func (h *Handler) auditMetaFromContext(c *gin.Context) AuditMeta {
	return AuditMeta{
		IP:        c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		RequestID: c.GetString(httpx.RequestIDKey),
	}
}

// list handles GET /projects/:project_id/assets.
func (h *Handler) list(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermAssetRead) {
		return
	}

	pq, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}

	// page_size is bounded to httpx.MaxPageSize by BindPageQuery, so the limit cast
	// cannot overflow. page_number has no upper bound there, so a hostile offset
	// ((page-1)*size) is rejected before narrowing to the int32 the sqlc query uses.
	const maxInt32 = 1<<31 - 1
	limit := int32(pq.Limit()) //nolint:gosec // G115: bounded to MaxPageSize (<=100) by BindPageQuery
	offset := pq.Offset()
	if offset > maxInt32 {
		httpx.BadRequest(c, "page_number out of range")
		return
	}
	rows, err := h.svc.List(c.Request.Context(), pid, limit, int32(offset)) //nolint:gosec // G115: guarded above
	if err != nil {
		httpx.Internal(c)
		return
	}
	total, err := h.svc.Count(c.Request.Context(), pid)
	if err != nil {
		httpx.Internal(c)
		return
	}

	items := make([]assetResponse, 0, len(rows))
	for _, a := range rows {
		items = append(items, toResponse(a))
	}
	httpx.OK(c, httpx.PageData[assetResponse]{
		Items:      items,
		Total:      total,
		PageSize:   pq.PageSize,
		PageNumber: pq.PageNumber,
	})
}

// detail handles GET /projects/:project_id/assets/:id.
func (h *Handler) detail(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermAssetRead) {
		return
	}
	id, ok := parseAssetID(c)
	if !ok {
		return
	}

	a, err := h.svc.GetByID(c.Request.Context(), pid, id)
	if err != nil {
		writeAssetErr(c, err)
		return
	}
	httpx.OK(c, toResponse(a))
}

// importAssets handles POST /projects/:project_id/assets/import. With the
// dry_run=true query flag it previews without writing; otherwise it commits the
// idempotent upsert for every row and reports per-row success/failure. The
// committed import and its audit event are written in one transaction by the
// service.
func (h *Handler) importAssets(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	p, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermAssetWrite) {
		return
	}

	var req importRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid import request")
		return
	}

	rows := make([]ImportInput, 0, len(req.Rows))
	for _, r := range req.Rows {
		rows = append(rows, ImportInput{
			AssetType:    r.AssetType,
			Value:        r.Value,
			DisplayName:  r.DisplayName,
			Source:       r.Source,
			Owner:        r.Owner,
			BusinessUnit: r.BusinessUnit,
			Confidence:   r.Confidence,
			Status:       r.Status,
		})
	}

	if parseDryRun(c) {
		report, err := h.svc.DryRun(c.Request.Context(), pid, rows)
		if err != nil {
			writeBatchErr(c, err)
			return
		}
		httpx.OK(c, report)
		return
	}

	// Real import: the asset's tenant/org derive from the project (resolved by
	// access), never from the request body, so a row cannot claim another
	// tenant's asset. The service writes the asset rows + the audit event in one
	// transaction.
	report, err := h.svc.ImportBatch(c.Request.Context(), ImportBatchInput{
		ProjectID: pid,
		TenantID:  p.TenantID,
		OrgID:     p.OrgID,
		ActorID:   c.GetString(auth.CtxUserID),
		Rows:      rows,
	}, h.auditMetaFromContext(c))
	if err != nil {
		// A failure here includes audit-write failures, which the service rolls
		// back — no committed change exists without an audit record. Log it so the
		// outage is visible to operators, then surface 500 to the caller.
		h.logServiceError(c, ActionAssetImport, err)
		writeBatchErr(c, err)
		return
	}
	httpx.OK(c, report)
}

// update handles PATCH /projects/:project_id/assets/:id. The edit and its audit
// event (before+after) are written in one transaction by the service.
func (h *Handler) update(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermAssetWrite) {
		return
	}
	id, ok := parseAssetID(c)
	if !ok {
		return
	}

	var req updateRequest
	// ShouldBindJSON with all-optional pointer fields never fails on missing
	// fields; it only fails on a malformed body.
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid update request")
		return
	}

	after, err := h.svc.Update(c.Request.Context(), pid, id, UpdateFields(req), c.GetString(auth.CtxUserID), h.auditMetaFromContext(c))
	if err != nil {
		h.logServiceError(c, ActionAssetUpdate, err)
		writeUpdateErr(c, err)
		return
	}
	httpx.OK(c, toResponse(after))
}

// access enforces the project access boundary and resolves the membership role
// in one call. It writes the response on denial and returns ok=false so the
// caller can return early. Unknown project → 404 (no access oracle); non-member
// → 403; other errors → 500.
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

// permit enforces the action permission via two independent, fail-closed paths:
//
//  1. Membership role path: the user's project_member role (from access) carries
//     the permission in the seeded role→permission matrix.
//  2. Explicit/global Casbin path: the user is granted the permission directly
//     for this project — covering global roles assigned via a grouping that the
//     matrix resolves, or a direct user policy. This is the path used by
//     cross-project admin roles that reach the project via project:access rather
//     than a project_member row (access returns role == "" on that path).
//
// Either path granting is sufficient; both failing yields 403.
func (h *Handler) permit(c *gin.Context, role string, pid uint64, permission string) bool {
	// Path 1: membership role against the matrix.
	if role != "" && h.enforcer.HasPolicy(role, asmcasbin.GlobalDomain, permission, "allow") {
		return true
	}
	// Path 2: explicit/global Casbin permission for this user in this project.
	userID := c.GetString(auth.CtxUserID)
	if ok, err := h.enforcer.Enforce(userID, strconv.FormatUint(pid, 10), permission, "allow"); err == nil && ok {
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

func parseAssetID(c *gin.Context) (uint64, bool) {
	raw := c.Param("id")
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		httpx.BadRequest(c, "invalid id")
		return 0, false
	}
	return id, true
}

// parseDryRun reads the dry_run query flag: "1" or "true" (case-insensitive)
// enable preview mode; anything else commits.
func parseDryRun(c *gin.Context) bool {
	switch c.Query("dry_run") {
	case "1", "true", "True", "TRUE":
		return true
	default:
		return false
	}
}

func writeAssetErr(c *gin.Context, err error) {
	if errors.Is(err, ErrNotFound) {
		httpx.NotFound(c, httpx.ErrCodeAssetNotFound, "asset not found")
		return
	}
	httpx.Internal(c)
}

// relationResponse is the external representation of a Relation. Direction is
// "out"/"in" relative to the queried asset on list responses; empty on create.
type relationResponse struct {
	ID           uint64 `json:"id"`
	ProjectID    uint64 `json:"project_id"`
	FromAssetID  uint64 `json:"from_asset_id"`
	ToAssetID    uint64 `json:"to_asset_id"`
	RelationType string `json:"relation_type"`
	Source       string `json:"source"`
	Confidence   uint8  `json:"confidence"`
	Direction    string `json:"direction,omitempty"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	CreatedBy    string `json:"created_by"`
	UpdatedBy    string `json:"updated_by"`
}

func toRelationResponse(r *Relation) relationResponse {
	return relationResponse{
		ID:           r.ID,
		ProjectID:    r.ProjectID,
		FromAssetID:  r.FromAssetID,
		ToAssetID:    r.ToAssetID,
		RelationType: r.RelationType,
		Source:       r.Source,
		Confidence:   r.Confidence,
		Direction:    r.Direction,
		FirstSeen:    r.FirstSeen.UTC().Format(timeRFC3339Millis),
		LastSeen:     r.LastSeen.UTC().Format(timeRFC3339Millis),
		CreatedAt:    r.CreatedAt.UTC().Format(timeRFC3339Millis),
		UpdatedAt:    r.UpdatedAt.UTC().Format(timeRFC3339Millis),
		CreatedBy:    r.CreatedBy,
		UpdatedBy:    r.UpdatedBy,
	}
}

// createRelationRequest is the POST /assets/:id/relations body. :id is the
// from-asset; the body names the to-asset and the edge type.
type createRelationRequest struct {
	ToAssetID    uint64 `json:"to_asset_id" binding:"required"`
	RelationType string `json:"relation_type" binding:"required"`
	Source       string `json:"source"`
	Confidence   uint8  `json:"confidence"`
}

// listRelations handles GET /projects/:project_id/assets/:id/relations.
func (h *Handler) listRelations(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermAssetRead) {
		return
	}
	id, ok := parseAssetID(c)
	if !ok {
		return
	}

	pq, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}
	const maxInt32 = 1<<31 - 1
	limit := int32(pq.Limit()) //nolint:gosec // G115: bounded to MaxPageSize by BindPageQuery
	offset := pq.Offset()
	if offset > maxInt32 {
		httpx.BadRequest(c, "page_number out of range")
		return
	}

	rows, total, err := h.svc.ListRelations(c.Request.Context(), pid, id, limit, int32(offset)) //nolint:gosec // G115: guarded above
	if err != nil {
		// A missing parent asset surfaces as ErrNotFound -> 404 ASSET_NOT_FOUND
		// (via writeAssetErr); other errors are 500.
		writeAssetErr(c, err)
		return
	}
	items := make([]relationResponse, 0, len(rows))
	for _, r := range rows {
		items = append(items, toRelationResponse(r))
	}
	httpx.OK(c, httpx.PageData[relationResponse]{
		Items:      items,
		Total:      total,
		PageSize:   pq.PageSize,
		PageNumber: pq.PageNumber,
	})
}

// createRelation handles POST /projects/:project_id/assets/:id/relations. The
// edge write and its audit event run in one transaction in the service.
func (h *Handler) createRelation(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	p, role, ok := h.access(c, pid)
	if !ok {
		return
	}
	if !h.permit(c, role, pid, asmcasbin.PermAssetWrite) {
		return
	}
	fromID, ok := parseAssetID(c)
	if !ok {
		return
	}

	var req createRelationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid relation request")
		return
	}

	rel, err := h.svc.UpsertRelation(c.Request.Context(), RelationInput{
		TenantID:     p.TenantID,
		OrgID:        p.OrgID,
		ProjectID:    pid,
		FromAssetID:  fromID,
		ToAssetID:    req.ToAssetID,
		RelationType: req.RelationType,
		Source:       req.Source,
		Confidence:   req.Confidence,
		ActorID:      c.GetString(auth.CtxUserID),
	}, h.auditMetaFromContext(c))
	if err != nil {
		h.logServiceError(c, ActionRelationSave, err)
		writeRelationErr(c, err)
		return
	}
	httpx.Created(c, toRelationResponse(rel))
}

func writeRelationErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrRelationEndpointNotFound):
		httpx.NotFound(c, httpx.ErrCodeAssetNotFound, "relation endpoint not found in project")
	case errors.Is(err, ErrInvalidRelationType):
		httpx.Unprocessable(c, "invalid relation_type")
	case errors.Is(err, ErrSelfRelation):
		httpx.Unprocessable(c, "self relation not allowed")
	case errors.Is(err, ErrMetadataTooLong):
		httpx.Unprocessable(c, "field too long")
	case errors.Is(err, ErrInvalidProjectID):
		httpx.BadRequest(c, "invalid project_id")
	default:
		// Includes transaction/audit-write failures: the service rolled the
		// change back, so the caller sees a failed request.
		httpx.Internal(c)
	}
}

func writeUpdateErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.NotFound(c, httpx.ErrCodeAssetNotFound, "asset not found")
	case errors.Is(err, ErrInvalidStatus):
		httpx.Unprocessable(c, "invalid status")
	case errors.Is(err, ErrMetadataTooLong):
		httpx.Unprocessable(c, "field too long")
	case errors.Is(err, ErrNoFields):
		httpx.BadRequest(c, "no fields to update")
	case errors.Is(err, ErrInvalidProjectID):
		httpx.BadRequest(c, "invalid project_id")
	default:
		httpx.Internal(c)
	}
}

func writeBatchErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrBatchTooLarge):
		httpx.BadRequest(c, "batch too large")
	case errors.Is(err, ErrInvalidProjectID):
		httpx.BadRequest(c, "invalid project_id")
	default:
		// Includes transaction/audit-write failures: the service rolled the
		// change back, so the caller sees a failed request, not a silent
		// un-audited change.
		httpx.Internal(c)
	}
}

// logServiceError logs a service-level failure (transaction or audit write) so
// the outage is visible to operators. A nil logger skips logging; the caller
// still returns a non-2xx, so the failure is not silent from the client's view.
func (h *Handler) logServiceError(c *gin.Context, action string, err error) {
	if h.logger == nil {
		return
	}
	h.logger.Error("asset change failed",
		"action", action,
		"actor", c.GetString(auth.CtxUserID),
		"project_id", c.Param("project_id"),
		"request_id", c.GetString(httpx.RequestIDKey),
		"error", err,
	)
}
