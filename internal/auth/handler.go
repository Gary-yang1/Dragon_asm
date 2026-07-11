package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

// Auth-specific error codes surfaced in the unified error envelope.
const (
	// #nosec G101 -- this is a machine-readable error code, not a credential.
	ErrCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrCodeInvalidRefresh     = "INVALID_REFRESH_TOKEN"
	ErrCodeCurrentPassword    = "INVALID_CURRENT_PASSWORD"
	ErrCodePasswordUnchanged  = "PASSWORD_UNCHANGED"
	ErrCodePasswordInvalid    = "INVALID_NEW_PASSWORD"
	ErrCodePasswordRequired   = "PASSWORD_CHANGE_REQUIRED"
)

// loginRequest is the POST /auth/login body. Bounds guard against oversized
// input; the username/password contents are otherwise opaque to the handler.
type loginRequest struct {
	Username string `json:"username" binding:"required,max=128"`
	Password string `json:"password" binding:"required,max=256"`
}

// refreshRequest is the POST /auth/refresh body.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required,max=4096"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,max=72"`
	NewPassword     string `json:"new_password" binding:"required,min=12,max=72"`
}

// tokenResponse is the refresh success payload.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// loginResponse is the login success payload consumed by the web shell.
type loginResponse struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	User         loginUserResponse `json:"user"`
}

type loginUserResponse struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Username           string   `json:"username"`
	DisplayName        string   `json:"display_name"`
	Role               string   `json:"role"`
	ProjectID          uint64   `json:"project_id"`
	Permissions        []string `json:"permissions"`
	MustChangePassword bool     `json:"must_change_password"`
}

// meResponse is the GET /auth/me payload. It deliberately omits password_hash
// and any secret.
type meResponse struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	DisplayName        string `json:"display_name"`
	TenantID           string `json:"tenant_id"`
	OrgID              string `json:"org_id"`
	MustChangePassword bool   `json:"must_change_password"`
}

// Handler adapts the auth Service to Gin HTTP routes.
type Handler struct {
	svc *Service
}

// NewHandler builds an auth HTTP handler over the service.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// RegisterRoutes mounts the auth endpoints under the given router groups.
// public is the unauthenticated group (login, refresh); protected requires a
// valid access token (me, permissions). The split enforces the "backend API
// default authenticated" architecture: business routes added to the protected
// group automatically get RequireAuth.
func (h *Handler) RegisterRoutes(public, protected *gin.RouterGroup) {
	public.POST("/auth/login", h.Login)
	public.POST("/auth/refresh", h.Refresh)

	protected.GET("/auth/me", h.Me)
	protected.GET("/auth/permissions", h.Permissions)
	protected.POST("/auth/password/change", h.ChangePassword)
}

func metaFromContext(c *gin.Context) RequestMeta {
	return RequestMeta{
		IP:        c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		RequestID: c.GetString(httpx.RequestIDKey),
	}
}

// Login handles POST /auth/login.
func (h *Handler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid login request")
		return
	}

	session, err := h.svc.LoginSession(c.Request.Context(), req.Username, req.Password, metaFromContext(c))
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			// Uniform 401 regardless of unknown user / bad password / disabled.
			httpx.Fail(c, http.StatusUnauthorized, ErrCodeInvalidCredentials, "invalid username or password")
			return
		}
		httpx.Internal(c)
		return
	}
	httpx.OK(c, toLoginResponse(session))
}

// Refresh handles POST /auth/refresh.
func (h *Handler) Refresh(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "invalid refresh request")
		return
	}

	pair, err := h.svc.Refresh(c.Request.Context(), req.RefreshToken, metaFromContext(c))
	if err != nil {
		if errors.Is(err, ErrInvalidRefreshToken) {
			httpx.Fail(c, http.StatusUnauthorized, ErrCodeInvalidRefresh, "invalid or expired refresh token")
			return
		}
		httpx.Internal(c)
		return
	}
	httpx.OK(c, tokenResponse{AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken})
}

// Me handles GET /auth/me. RequireAuth has already validated the token and set
// the user id in the context.
func (h *Handler) Me(c *gin.Context) {
	userID := c.GetString(CtxUserID)
	user, err := h.svc.Me(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Token is valid but the principal no longer exists — treat as
			// unauthenticated rather than leaking a 404 for a valid token.
			httpx.Unauthorized(c)
			return
		}
		httpx.Internal(c)
		return
	}
	httpx.OK(c, meResponse{
		ID:                 actorID(user.ID),
		Username:           user.Username,
		DisplayName:        user.DisplayName,
		TenantID:           user.TenantID,
		OrgID:              user.OrgID,
		MustChangePassword: user.MustChangePassword,
	})
}

// ChangePassword replaces the authenticated user's current or temporary
// password. Existing tokens are revoked through auth_version.
func (h *Handler) ChangePassword(c *gin.Context) {
	var req changePasswordRequest
	if c.ShouldBindJSON(&req) != nil {
		httpx.BadRequest(c, "invalid password change request")
		return
	}
	err := h.svc.ChangePassword(
		c.Request.Context(), c.GetString(CtxUserID), req.CurrentPassword, req.NewPassword, metaFromContext(c),
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrCurrentPasswordInvalid):
			httpx.Fail(c, http.StatusUnprocessableEntity, ErrCodeCurrentPassword, "current password is invalid")
		case errors.Is(err, ErrPasswordUnchanged):
			httpx.Fail(c, http.StatusUnprocessableEntity, ErrCodePasswordUnchanged, "new password must differ")
		case errors.Is(err, ErrPasswordInvalid):
			httpx.Fail(c, http.StatusUnprocessableEntity, ErrCodePasswordInvalid, "invalid new password")
		case errors.Is(err, ErrUserNotFound):
			httpx.Unauthorized(c)
		default:
			httpx.Internal(c)
		}
		return
	}
	httpx.OK(c, gin.H{"must_change_password": false})
}

// Permissions handles GET /auth/permissions.
func (h *Handler) Permissions(c *gin.Context) {
	userID := c.GetString(CtxUserID)
	perms, err := h.svc.Permissions(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httpx.Unauthorized(c)
			return
		}
		httpx.Internal(c)
		return
	}
	httpx.OK(c, gin.H{"permissions": perms})
}

func toLoginResponse(session *LoginSession) loginResponse {
	user := session.User
	role := ""
	var projectID uint64
	if session.Membership != nil {
		role = session.Membership.Role
		projectID = session.Membership.ProjectID
	}
	return loginResponse{
		AccessToken:  session.TokenPair.AccessToken,
		RefreshToken: session.TokenPair.RefreshToken,
		User: loginUserResponse{
			ID:                 actorID(user.ID),
			Name:               user.DisplayName,
			Username:           user.Username,
			DisplayName:        user.DisplayName,
			Role:               role,
			ProjectID:          projectID,
			Permissions:        session.Permissions,
			MustChangePassword: user.MustChangePassword,
		},
	}
}
