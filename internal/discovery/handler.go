//revive:disable:exported

package discovery

import (
	"errors"
	"io"
	"log/slog"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

const (
	headerCallbackSignature = "X-Signature"
	headerCallbackTimestamp = "X-Timestamp"
)

// Handler adapts discovery callback endpoints to Gin.
type Handler struct {
	svc    *Service
	secret string
	logger *slog.Logger
}

func NewHandler(svc *Service, callbackSecret string, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, secret: callbackSecret, logger: logger}
}

// RegisterPublicRoutes mounts HMAC-protected engine callback routes. These are
// intentionally not JWT protected because the caller is the external engine.
func (h *Handler) RegisterPublicRoutes(public *gin.RouterGroup) {
	g := public.Group("/discovery")
	g.POST("/callback", h.callback)
}

func (h *Handler) callback(c *gin.Context) {
	projectID, ok := parseUintQuery(c, "project_id")
	if !ok {
		return
	}
	runID, ok := parseUintQuery(c, "run_id")
	if !ok {
		return
	}
	seq, ok := parseUintQuery(c, "seq")
	if !ok {
		return
	}
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		httpx.BadRequest(c, "invalid request body")
		return
	}

	result, err := h.svc.HandleCallback(c.Request.Context(), HandleCallbackInput{
		ProjectID: projectID,
		RunID:     runID,
		Seq:       seq,
		Timestamp: c.GetHeader(headerCallbackTimestamp),
		Signature: c.GetHeader(headerCallbackSignature),
		RawBody:   raw,
		Secret:    h.secret,
	})
	if err != nil {
		h.writeCallbackError(c, err)
		return
	}
	httpx.OK(c, gin.H{"duplicate": result.Duplicate})
}

func (h *Handler) writeCallbackError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrInvalidCallbackSignature), errors.Is(err, ErrCallbackReplay):
		httpx.Unauthorized(c)
	case errors.Is(err, ErrInvalidCallbackPayload):
		httpx.BadRequest(c, "invalid callback payload")
	case errors.Is(err, ErrCallbackRunNotRunning), errors.Is(err, ErrInvalidRunTransition):
		httpx.Conflict(c, httpx.ErrCodeInvalidTransition, "callback run is not running")
	case errors.Is(err, ErrNotFound):
		httpx.NotFound(c, "DISCOVERY_RUN_NOT_FOUND", "discovery run not found")
	case errors.Is(err, ErrCallbackEnqueue):
		if h.logger != nil {
			h.logger.Error("callback enqueue failed", "error", err)
		}
		httpx.Internal(c)
	default:
		if h.logger != nil {
			h.logger.Error("callback handling failed", "error", err)
		}
		httpx.Internal(c)
	}
}

func parseUintQuery(c *gin.Context, key string) (uint64, bool) {
	raw := c.Query(key)
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || v == 0 {
		httpx.BadRequest(c, key+" must be a positive integer")
		return 0, false
	}
	return v, true
}
