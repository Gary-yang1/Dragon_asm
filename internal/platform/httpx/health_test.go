package httpx_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func TestHealthCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	engine := httpx.NewEngine(logger)
	httpx.RegisterHealthRoute(engine.Group("/"), "test")

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/healthz", nil)
	require.NoError(t, err)

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body httpx.HealthStatus
	err = json.NewDecoder(w.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body.Status)
	assert.Equal(t, "test", body.Version)
}

func TestRequestIDValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	engine := httpx.NewEngine(logger)
	httpx.RegisterHealthRoute(engine.Group("/"), "test")

	cases := []struct {
		name    string
		inID    string
		wantSrc string // "caller" or "generated"
	}{
		{"valid alphanumeric", "abc123", "caller"},
		{"valid with hyphen", "req-abc-123", "caller"},
		{"valid with underscore", "req_abc_123", "caller"},
		{"too long", string(make([]byte, 129)), "generated"},
		{"contains newline", "req\n123", "generated"},
		{"contains spaces", "req 123", "generated"},
		{"contains special chars", "req<script>", "generated"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodGet, "/healthz", nil)
			require.NoError(t, err)
			if tc.inID != "" {
				req.Header.Set("X-Request-ID", tc.inID)
			}
			engine.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			gotID := w.Header().Get("X-Request-ID")
			assert.NotEmpty(t, gotID)
			if tc.wantSrc == "caller" {
				assert.Equal(t, tc.inID, gotID)
			} else {
				assert.NotEqual(t, tc.inID, gotID, "invalid ID should be replaced")
			}
		})
	}
}
