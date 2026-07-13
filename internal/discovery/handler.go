//revive:disable:exported

package discovery

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

const (
	headerCallbackSignature = "X-Signature"
	headerCallbackTimestamp = "X-Timestamp"
	headerCallbackEngineID  = "X-Engine-ID"
)

// Handler adapts discovery callback endpoints to Gin.
type Handler struct {
	svc         *Service
	legacyOnly  string
	credentials *CallbackCredentialSet
	logger      *slog.Logger
}

func NewHandler(svc *Service, callbackSecret string, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, legacyOnly: callbackSecret, logger: logger}
}

// NewIdentityBoundHandler requires callbacks to identify the configured engine.
// NewHandler remains for legacy rows/tests whose callback_secret_ref is empty.
func NewIdentityBoundHandler(svc *Service, engineID, callbackSecret string, logger *slog.Logger) (*Handler, error) {
	credentials, err := NewCallbackCredentialSet(engineID, callbackSecret, "")
	if err != nil {
		return nil, err
	}
	return NewCredentialBoundHandler(svc, credentials, logger)
}

// NewCredentialBoundHandler supports bounded multi-identity callback secrets
// so in-flight runs keep their original secret ref during key rotation.
func NewCredentialBoundHandler(svc *Service, credentials *CallbackCredentialSet, logger *slog.Logger) (*Handler, error) {
	if svc == nil || credentials == nil || credentials.ActiveRef() == "" {
		return nil, ErrInvalidCallbackIdentity
	}
	return &Handler{svc: svc, credentials: credentials, logger: logger}, nil
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
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, callbackMaxBodyBytes)
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httpx.Fail(c, http.StatusRequestEntityTooLarge, "CALLBACK_TOO_LARGE", "callback payload too large", nil)
			return
		}
		httpx.BadRequest(c, "invalid request body")
		return
	}

	secretRef := strings.TrimSpace(c.GetHeader(headerCallbackEngineID))
	secret := h.legacyOnly
	if h.credentials != nil {
		secret = h.credentials.secretFor(secretRef)
	}
	result, err := h.svc.HandleCallback(c.Request.Context(), HandleCallbackInput{
		ProjectID: projectID,
		RunID:     runID,
		Seq:       seq,
		SecretRef: secretRef,
		Timestamp: c.GetHeader(headerCallbackTimestamp),
		Signature: c.GetHeader(headerCallbackSignature),
		RawBody:   raw,
		Secret:    secret,
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
	case errors.Is(err, ErrCallbackSchemaUnsupported):
		httpx.Fail(c, http.StatusUnprocessableEntity, "CALLBACK_SCHEMA_UNSUPPORTED", "callback schema version is unsupported", nil)
	case errors.Is(err, ErrCallbackTooLarge):
		httpx.Fail(c, http.StatusRequestEntityTooLarge, "CALLBACK_TOO_LARGE", "callback payload too large", nil)
	case errors.Is(err, ErrCallbackPayloadConflict):
		httpx.Fail(c, http.StatusConflict, "CALLBACK_PAYLOAD_CONFLICT", "callback sequence payload conflicts with the accepted payload", nil)
	case errors.Is(err, ErrCallbackRunNotRunning), errors.Is(err, ErrInvalidRunTransition):
		httpx.Conflict(c, httpx.ErrCodeInvalidTransition, "callback run is not running")
	case errors.Is(err, ErrNotFound):
		httpx.NotFound(c, "DISCOVERY_RUN_NOT_FOUND", "discovery run not found")
	case errors.Is(err, ErrCallbackEnqueue):
		if h.logger != nil {
			h.logger.Error("callback enqueue failed", "error", err)
		}
		httpx.Fail(c, http.StatusServiceUnavailable, "CALLBACK_INGEST_UNAVAILABLE", "callback accepted but ingest queue is temporarily unavailable", nil)
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
