package httpx

import (
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
)

// DefaultMaxBodyBytes is the coarse request-body ceiling applied to every route.
// It is a backstop against unbounded reads, not a business rule: handlers that
// need a tighter bound (the discovery callback caps itself at 4 MiB) re-wrap the
// body themselves, and the tighter limit wins.
const DefaultMaxBodyBytes int64 = 8 << 20

// MaxBodyBytes caps how much of a request body a handler can read. Without it a
// caller can force the server to buffer an arbitrarily large JSON document
// before any application-level batch limit (for example the 500-row asset
// import cap) gets a chance to reject it.
func MaxBodyBytes(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}

// SecurityHeaders sets the response headers that harden a JSON API against
// content sniffing, framing, and referrer leakage. The CSP is deliberately
// `default-src 'none'` because this server only ever returns JSON and file
// attachments — the SPA is served separately.
//
// HSTS is emitted only for requests that actually arrived over TLS. Asserting it
// over plaintext HTTP would be ignored by browsers and would pin developers
// running the local HTTP stack onto https for the whole host.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// Responses carry asset, risk, and ticket data; keep them out of shared caches.
		h.Set("Cache-Control", "no-store")
		if c.Request.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}

// maxBodyBytesFromEnv reads API_MAX_BODY_BYTES, falling back to
// DefaultMaxBodyBytes when unset, unparsable, or non-positive.
func maxBodyBytesFromEnv() int64 {
	raw := os.Getenv("API_MAX_BODY_BYTES")
	if raw == "" {
		return DefaultMaxBodyBytes
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return DefaultMaxBodyBytes
	}
	return n
}
