package httpx_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	engine := httpx.NewEngine(logger)
	httpx.RegisterHealthRoute(engine.Group("/"), "test")

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/healthz", nil)
	require.NoError(t, err)
	engine.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "same-origin", w.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'none'")
	// HSTS must not be asserted over plaintext HTTP.
	assert.Empty(t, w.Header().Get("Strict-Transport-Security"))
}

func TestMaxBodyBytesRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(httpx.MaxBodyBytes(64))
	engine.POST("/echo", func(c *gin.Context) {
		var body map[string]any
		if err := c.ShouldBindJSON(&body); err != nil {
			httpx.BadRequest(c, "body rejected")
			return
		}
		httpx.OK(c, body)
	})

	t.Run("within limit", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodPost, "/echo", strings.NewReader(`{"a":"b"}`))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		engine.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("over limit", func(t *testing.T) {
		oversized := `{"a":"` + strings.Repeat("x", 512) + `"}`
		w := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodPost, "/echo", strings.NewReader(oversized))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		engine.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code,
			"a body past the cap must not be buffered and decoded")
	})
}

func TestRateLimitByIPReturns429AfterBurst(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(httpx.RateLimitByIP(httpx.RateLimitConfig{Rate: 3, Window: time.Minute, Burst: 3}))
	engine.POST("/login", func(c *gin.Context) { httpx.OK(c, gin.H{"ok": true}) })

	call := func(remoteAddr string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodPost, "/login", bytes.NewReader(nil))
		require.NoError(t, err)
		req.RemoteAddr = remoteAddr
		engine.ServeHTTP(w, req)
		return w
	}

	for i := 0; i < 3; i++ {
		assert.Equal(t, http.StatusOK, call("10.1.1.1:1234").Code, "request %d within burst", i+1)
	}

	blocked := call("10.1.1.1:1234")
	assert.Equal(t, http.StatusTooManyRequests, blocked.Code)
	assert.Equal(t, "60", blocked.Header().Get("Retry-After"))
	assert.Contains(t, blocked.Body.String(), httpx.ErrCodeTooManyRequests)

	// A different address has its own bucket — one grinder must not lock out others.
	assert.Equal(t, http.StatusOK, call("10.2.2.2:1234").Code)
}

func TestClientIPIgnoresForwardedHeaderByDefault(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	engine := httpx.NewEngine(logger)

	var seen string
	engine.GET("/whoami", func(c *gin.Context) {
		seen = c.ClientIP()
		httpx.OK(c, gin.H{"ip": seen})
	})

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/whoami", nil)
	require.NoError(t, err)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	engine.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "203.0.113.9", seen,
		"an untrusted caller must not be able to forge the audited client IP")
}

func TestClientIPHonoursConfiguredTrustedProxy(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "203.0.113.0/24")
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	engine := httpx.NewEngine(logger)

	var seen string
	engine.GET("/whoami", func(c *gin.Context) {
		seen = c.ClientIP()
		httpx.OK(c, gin.H{"ip": seen})
	})

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/whoami", nil)
	require.NoError(t, err)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	engine.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "1.2.3.4", seen, "a listed proxy may report the real client")
}
