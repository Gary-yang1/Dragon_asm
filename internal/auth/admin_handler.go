package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

// Platform-user error codes are stable machine-readable API values.
const (
	ErrCodePlatformUserNotFound  = "PLATFORM_USER_NOT_FOUND"
	ErrCodeUsernameConflict      = "USERNAME_CONFLICT"
	ErrCodeLastSystemAdmin       = "LAST_SYSTEM_ADMIN"
	ErrCodeSelfDisableForbidden  = "SELF_DISABLE_FORBIDDEN"
	ErrCodeInvalidUserTransition = "INVALID_USER_TRANSITION"
)

// AdminUserHandler exposes tenant-scoped platform-user administration routes.
type AdminUserHandler struct {
	service *AdminUserService
}

// NewAdminUserHandler creates a platform-user HTTP handler.
func NewAdminUserHandler(service *AdminUserService) *AdminUserHandler {
	return &AdminUserHandler{service: service}
}

// RegisterRoutes mounts all platform-user endpoints on an authenticated group.
func (h *AdminUserHandler) RegisterRoutes(protected *gin.RouterGroup) {
	admin := protected.Group("/admin")
	admin.GET("/users", h.list)
	admin.POST("/users", h.create)
	admin.GET("/users/:user_id", h.detail)
	admin.PATCH("/users/:user_id", h.update)
	admin.POST("/users/:user_id/transitions", h.transition)
	admin.POST("/users/:user_id/password-reset", h.resetPassword)
	admin.PUT("/users/:user_id/tenant-role", h.updateTenantRole)
	admin.GET("/users/:user_id/projects", h.projects)
	admin.GET("/roles", h.roles)
}

type createPlatformUserRequest struct {
	Username   string  `json:"username" binding:"required,max=128"`
	Name       string  `json:"name" binding:"required,max=255"`
	Email      string  `json:"email" binding:"omitempty,email,max=255"`
	Phone      string  `json:"phone" binding:"omitempty,max=32"`
	Department string  `json:"department" binding:"omitempty,max=128"`
	Role       *string `json:"role"`
	Status     string  `json:"status" binding:"omitempty,oneof=active disabled"`
	Password   string  `json:"password" binding:"required,min=12,max=72"`
}

type updatePlatformUserRequest struct {
	Name       *string `json:"name" binding:"omitempty,max=255"`
	Email      *string `json:"email" binding:"omitempty,email,max=255"`
	Phone      *string `json:"phone" binding:"omitempty,max=32"`
	Department *string `json:"department" binding:"omitempty,max=128"`
}

type transitionPlatformUserRequest struct {
	Status string `json:"status" binding:"required,oneof=active disabled"`
	Reason string `json:"reason" binding:"required,max=512"`
}

type resetPlatformUserPasswordRequest struct {
	TemporaryPassword string `json:"temporary_password" binding:"required,min=12,max=72"`
}

type updateTenantRoleRequest struct {
	Role json.RawMessage `json:"role" binding:"required"`
}

type platformUserResponse struct {
	ID                 uint64     `json:"id"`
	Username           string     `json:"username"`
	Name               string     `json:"name"`
	Email              string     `json:"email"`
	Phone              string     `json:"phone"`
	Department         string     `json:"department"`
	Role               *string    `json:"role"`
	ProjectCount       int64      `json:"project_count"`
	Status             string     `json:"status"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	MustChangePassword bool       `json:"must_change_password"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type platformUserProjectResponse struct {
	ID          uint64    `json:"id"`
	ProjectCode string    `json:"project_code"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	Status      string    `json:"status"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type adminRoleResponse struct {
	Value       string   `json:"value"`
	Label       string   `json:"label"`
	Scope       string   `json:"scope"`
	Permissions []string `json:"permissions"`
}

func (h *AdminUserHandler) list(c *gin.Context) {
	page, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}
	if page.Offset() > 1<<31-1 {
		httpx.BadRequest(c, "page_number out of range")
		return
	}
	list, err := h.service.List(c.Request.Context(), c.GetString(CtxUserID), PlatformUserListFilter{
		Search: c.Query("q"), Status: c.Query("status"), Role: c.Query("role"),
		Limit: int32(page.Limit()), Offset: int32(page.Offset()), //nolint:gosec // guarded above.
	})
	if err != nil {
		writeAdminUserError(c, err)
		return
	}
	items := make([]platformUserResponse, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, platformUserDTO(item))
	}
	httpx.OK(c, httpx.PageData[platformUserResponse]{
		Items: items, Total: list.Total, PageSize: page.PageSize, PageNumber: page.PageNumber,
	})
}

func (h *AdminUserHandler) create(c *gin.Context) {
	var request createPlatformUserRequest
	if c.ShouldBindJSON(&request) != nil {
		httpx.BadRequest(c, "invalid platform user request")
		return
	}
	role := ""
	if request.Role != nil {
		role = *request.Role
	}
	created, err := h.service.Create(c.Request.Context(), CreatePlatformUserInput{
		Username: request.Username, DisplayName: request.Name, Email: request.Email, Phone: request.Phone,
		Department: request.Department, Role: role, Status: request.Status, Password: request.Password,
		ActorID: c.GetString(CtxUserID), Meta: adminMeta(c),
	})
	if err != nil {
		writeAdminUserError(c, err)
		return
	}
	httpx.Created(c, platformUserDTO(created))
}

func (h *AdminUserHandler) detail(c *gin.Context) {
	userID, ok := adminUserID(c)
	if !ok {
		return
	}
	user, err := h.service.Get(c.Request.Context(), c.GetString(CtxUserID), userID)
	if err != nil {
		writeAdminUserError(c, err)
		return
	}
	httpx.OK(c, platformUserDTO(user))
}

func (h *AdminUserHandler) update(c *gin.Context) {
	userID, ok := adminUserID(c)
	if !ok {
		return
	}
	var request updatePlatformUserRequest
	if c.ShouldBindJSON(&request) != nil {
		httpx.BadRequest(c, "invalid platform user request")
		return
	}
	updated, err := h.service.Update(c.Request.Context(), UpdatePlatformUserInput{
		UserID: userID, DisplayName: request.Name, Email: request.Email, Phone: request.Phone,
		Department: request.Department, ActorID: c.GetString(CtxUserID), Meta: adminMeta(c),
	})
	if err != nil {
		writeAdminUserError(c, err)
		return
	}
	httpx.OK(c, platformUserDTO(updated))
}

func (h *AdminUserHandler) transition(c *gin.Context) {
	userID, ok := adminUserID(c)
	if !ok {
		return
	}
	var request transitionPlatformUserRequest
	if c.ShouldBindJSON(&request) != nil {
		httpx.BadRequest(c, "invalid platform user transition")
		return
	}
	updated, err := h.service.Transition(c.Request.Context(), TransitionPlatformUserInput{
		UserID: userID, Status: request.Status, Reason: request.Reason,
		ActorID: c.GetString(CtxUserID), Meta: adminMeta(c),
	})
	if err != nil {
		writeAdminUserError(c, err)
		return
	}
	httpx.OK(c, platformUserDTO(updated))
}

func (h *AdminUserHandler) resetPassword(c *gin.Context) {
	userID, ok := adminUserID(c)
	if !ok {
		return
	}
	var request resetPlatformUserPasswordRequest
	if c.ShouldBindJSON(&request) != nil {
		httpx.BadRequest(c, "invalid password reset request")
		return
	}
	if err := h.service.ResetPassword(c.Request.Context(), ResetPlatformUserPasswordInput{
		UserID: userID, TemporaryPassword: request.TemporaryPassword,
		ActorID: c.GetString(CtxUserID), Meta: adminMeta(c),
	}); err != nil {
		writeAdminUserError(c, err)
		return
	}
	httpx.OK(c, gin.H{"user_id": userID, "must_change_password": true})
}

func (h *AdminUserHandler) updateTenantRole(c *gin.Context) {
	userID, ok := adminUserID(c)
	if !ok {
		return
	}
	var request updateTenantRoleRequest
	if c.ShouldBindJSON(&request) != nil {
		httpx.BadRequest(c, "invalid tenant role request")
		return
	}
	role, err := parseNullableTenantRole(request.Role)
	if err != nil {
		httpx.BadRequest(c, "invalid tenant role request")
		return
	}
	updated, err := h.service.UpdateTenantRole(c.Request.Context(), UpdateTenantRoleInput{
		UserID: userID, Role: role, ActorID: c.GetString(CtxUserID), Meta: adminMeta(c),
	})
	if err != nil {
		writeAdminUserError(c, err)
		return
	}
	httpx.OK(c, gin.H{"user_id": updated.ID, "role": tenantRolePointer(updated.Role)})
}

func parseNullableTenantRole(raw json.RawMessage) (string, error) {
	if string(raw) == "null" {
		return "", nil
	}
	var role string
	if err := json.Unmarshal(raw, &role); err != nil {
		return "", err
	}
	return role, nil
}

func (h *AdminUserHandler) projects(c *gin.Context) {
	userID, ok := adminUserID(c)
	if !ok {
		return
	}
	projects, err := h.service.ListProjects(c.Request.Context(), c.GetString(CtxUserID), userID)
	if err != nil {
		writeAdminUserError(c, err)
		return
	}
	items := make([]platformUserProjectResponse, 0, len(projects))
	for _, project := range projects {
		items = append(items, platformUserProjectResponse(project))
	}
	httpx.OK(c, gin.H{"items": items})
}

func (h *AdminUserHandler) roles(c *gin.Context) {
	roles, err := h.service.Roles(c.Request.Context(), c.GetString(CtxUserID))
	if err != nil {
		writeAdminUserError(c, err)
		return
	}
	items := make([]adminRoleResponse, 0, len(roles))
	for _, role := range roles {
		items = append(items, adminRoleResponse(role))
	}
	httpx.OK(c, items)
}

func platformUserDTO(user *PlatformUser) platformUserResponse {
	return platformUserResponse{
		ID: user.ID, Username: user.Username, Name: user.DisplayName, Email: user.Email,
		Phone: user.Phone, Department: user.Department, Role: tenantRolePointer(user.Role),
		ProjectCount: user.ProjectCount, Status: user.Status, LastLoginAt: user.LastLoginAt,
		MustChangePassword: user.MustChangePassword, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
	}
}

func tenantRolePointer(role string) *string {
	if role == "" {
		return nil
	}
	value := role
	return &value
}

func adminUserID(c *gin.Context) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param("user_id"), 10, 64)
	if err != nil || id == 0 {
		httpx.BadRequest(c, "invalid user_id")
		return 0, false
	}
	return id, true
}

func adminMeta(c *gin.Context) AdminAuditMeta {
	return AdminAuditMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent(), RequestID: c.GetString(httpx.RequestIDKey)}
}

func writeAdminUserError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrAdminForbidden):
		httpx.Forbidden(c)
	case errors.Is(err, ErrAdminUserNotFound):
		httpx.NotFound(c, ErrCodePlatformUserNotFound, "platform user not found")
	case errors.Is(err, ErrUsernameConflict):
		httpx.Conflict(c, ErrCodeUsernameConflict, "username already exists")
	case errors.Is(err, ErrLastSystemAdmin):
		httpx.Conflict(c, ErrCodeLastSystemAdmin, "the tenant must retain an active system administrator")
	case errors.Is(err, ErrAdminSelfDisable):
		httpx.Fail(c, http.StatusConflict, ErrCodeSelfDisableForbidden, "the current user cannot be disabled")
	case errors.Is(err, ErrAdminInvalidTransition):
		httpx.Fail(c, http.StatusConflict, ErrCodeInvalidUserTransition, "invalid platform user state transition")
	case errors.Is(err, ErrAdminInvalidInput), errors.Is(err, ErrAdminInvalidStatus), errors.Is(err, ErrAdminInvalidRole):
		httpx.Unprocessable(c, "invalid platform user input")
	default:
		httpx.Internal(c)
	}
}
