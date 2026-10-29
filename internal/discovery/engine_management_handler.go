package discovery

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

// EngineManagementHandler exposes system-administrator-only platform engine
// visibility. Permission checks remain in the service so direct callers cannot
// bypass them.
type EngineManagementHandler struct {
	service *EngineManagementService
}

// NewEngineManagementHandler binds the authenticated engine management API.
func NewEngineManagementHandler(service *EngineManagementService) *EngineManagementHandler {
	return &EngineManagementHandler{service: service}
}

// RegisterRoutes attaches management endpoints to the authenticated route group.
func (h *EngineManagementHandler) RegisterRoutes(protected *gin.RouterGroup) {
	engines := protected.Group("/platform/discovery-engines")
	engines.GET("", h.list)
	engines.POST("/:route/check", h.check)
	engines.GET("/configuration", h.configuration)
	engines.PUT("/configuration", h.updateConfiguration)
}

func (h *EngineManagementHandler) list(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if h == nil || h.service == nil {
		httpx.Internal(c)
		return
	}
	overview, err := h.service.List(c.Request.Context(), c.GetString(auth.CtxUserID))
	if err != nil {
		writeEngineManagementError(c, err)
		return
	}
	httpx.OK(c, overview)
}

func (h *EngineManagementHandler) check(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if h == nil || h.service == nil {
		httpx.Internal(c)
		return
	}
	summary, err := h.service.Check(
		c.Request.Context(), c.GetString(auth.CtxUserID), EngineRoute(c.Param("route")), managementMeta(c),
	)
	if err != nil {
		writeEngineManagementError(c, err)
		return
	}
	httpx.OK(c, summary)
}

func writeEngineManagementError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrEngineSettingsInvalid):
		httpx.Unprocessable(c, ErrEngineSettingsInvalid.Error())
	case errors.Is(err, ErrEngineSettingsConflict):
		httpx.Fail(c, http.StatusConflict, "ENGINE_SETTINGS_CONFLICT", ErrEngineSettingsConflict.Error())
	case errors.Is(err, ErrEngineSettingsUnavailable), errors.Is(err, ErrProviderSettingsUnavailable):
		httpx.Fail(c, http.StatusServiceUnavailable, "ENGINE_SETTINGS_UNAVAILABLE", err.Error())
	case errors.Is(err, ErrEngineManagementForbidden):
		httpx.Forbidden(c)
	case errors.Is(err, ErrEngineManagementInvalidRoute):
		httpx.Unprocessable(c, "invalid discovery engine route")
	case errors.Is(err, ErrEngineManagementUnavailable):
		httpx.Fail(c, http.StatusServiceUnavailable, "ENGINE_MANAGEMENT_UNAVAILABLE", "engine management is temporarily unavailable")
	default:
		httpx.Internal(c)
	}
}

func (h *EngineManagementHandler) configuration(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	view, err := h.service.Configuration(c.Request.Context(), c.GetString(auth.CtxUserID))
	if err != nil {
		writeEngineManagementError(c, err)
		return
	}
	httpx.OK(c, view)
}
func (h *EngineManagementHandler) updateConfiguration(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var in UpdateEngineSettingsInput
	if err := decoder.Decode(&in); err != nil {
		httpx.Unprocessable(c, "配置请求格式无效")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		httpx.Unprocessable(c, "配置请求格式无效")
		return
	}
	view, err := h.service.UpdateConfiguration(c.Request.Context(), c.GetString(auth.CtxUserID), in, managementMeta(c))
	if err != nil {
		writeEngineManagementError(c, err)
		return
	}
	httpx.OK(c, view)
}
