package httpx

import (
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// requestIDMaxLen is the maximum accepted length for a caller-supplied X-Request-ID.
const requestIDMaxLen = 128

// requestIDPattern accepts ASCII alphanumeric, hyphen, and underscore only.
// This prevents log-injection via a crafted X-Request-ID header.
var requestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)

// NewEngine returns a Gin engine with the standard middleware stack.
// Callers register routes on the returned engine.
//
// Trusted proxies are configured here rather than left at Gin's default. Gin
// defaults to trusting every proxy, which makes c.ClientIP() return whatever
// X-Forwarded-For the caller sends — and that value lands in the audit trail for
// logins, asset imports, and risk decisions. See SetTrustedProxiesFromEnv.
func NewEngine(logger *slog.Logger) *gin.Engine {
	engine := gin.New()
	if err := SetTrustedProxiesFromEnv(engine); err != nil {
		logger.Warn("trusted proxies rejected; falling back to trusting none",
			"env", trustedProxiesEnv, "error", err)
		_ = engine.SetTrustedProxies(nil)
	}

	engine.Use(
		middlewareRequestID(),
		SecurityHeaders(),
		MaxBodyBytes(maxBodyBytesFromEnv()),
		middlewareLogger(logger),
		middlewareRecovery(logger),
	)

	return engine
}

// trustedProxiesEnv holds a comma-separated list of proxy CIDRs or addresses
// allowed to set X-Forwarded-For.
const trustedProxiesEnv = "TRUSTED_PROXIES"

// SetTrustedProxiesFromEnv configures which upstream hops may rewrite the client
// address. The default — TRUSTED_PROXIES unset — trusts nothing, so ClientIP()
// is the TCP peer and cannot be forged. Operators terminating TLS at a proxy
// must list that proxy's CIDR, otherwise every audit record shows the proxy IP.
func SetTrustedProxiesFromEnv(engine *gin.Engine) error {
	raw := strings.TrimSpace(os.Getenv(trustedProxiesEnv))
	if raw == "" {
		return engine.SetTrustedProxies(nil)
	}
	parts := strings.Split(raw, ",")
	proxies := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			proxies = append(proxies, p)
		}
	}
	return engine.SetTrustedProxies(proxies)
}

// middlewareRequestID injects a unique request ID into every request context
// and response header. If the caller supplies X-Request-ID it is validated
// (max 128 chars, ASCII alphanumeric/hyphen/underscore) before use; an
// invalid value is silently replaced with a freshly generated UUID to avoid
// log-injection while still ensuring every request has a traceable ID.
func middlewareRequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" || len(id) > requestIDMaxLen || !requestIDPattern.MatchString(id) {
			id = uuid.NewString()
		}
		c.Set(RequestIDKey, id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

// middlewareLogger logs each request using structured slog output.
// Sensitive headers (Authorization, Cookie, Set-Cookie) are never logged.
func middlewareLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		logger.Info("http",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latency_ms", time.Since(start).Milliseconds(),
			"request_id", c.GetString(RequestIDKey),
			"client_ip", c.ClientIP(),
		)
	}
}

// middlewareRecovery catches panics, logs them, and returns a 500.
func middlewareRecovery(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("panic recovered",
					"error", r,
					"request_id", c.GetString(RequestIDKey),
					"path", c.Request.URL.Path,
				)
				c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse{
					RequestID: c.GetString(RequestIDKey),
					Error: ErrorDetail{
						Code:    ErrCodeInternalServer,
						Message: "an unexpected error occurred",
					},
				})
			}
		}()
		c.Next()
	}
}
