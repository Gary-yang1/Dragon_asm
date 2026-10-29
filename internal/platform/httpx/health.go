package httpx

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthStatus is the health check response body.
type HealthStatus struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// ReadinessStatus is the readiness probe response body. Checks maps a dependency
// name to "ok" or "error" — never to the underlying error, which could carry a
// DSN or hostname.
type ReadinessStatus struct {
	Status  string            `json:"status"`
	Version string            `json:"version"`
	Checks  map[string]string `json:"checks"`
}

// ReadinessCheck reports whether one dependency is usable.
type ReadinessCheck func(ctx context.Context) error

// readinessTimeout bounds the whole probe so a hung dependency cannot pile up
// probe requests.
const readinessTimeout = 2 * time.Second

// RegisterHealthRoute mounts GET /healthz on the given router group.
//
// This is a liveness probe only: it answers 200 as long as the process can serve
// HTTP. Use RegisterReadyRoute to decide whether the process should receive
// traffic — the API deliberately starts with its business routes unwired when a
// prerequisite is missing, and liveness cannot see that.
func RegisterHealthRoute(rg *gin.RouterGroup, version string) {
	rg.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, HealthStatus{
			Status:  "ok",
			Version: version,
		})
	})
}

// RegisterReadyRoute mounts GET /readyz, answering 503 unless every check passes.
//
// It exists because the API is fail-closed: when JWT secrets are missing or the
// database is unreachable at boot, main leaves /api/v1 unwired and keeps serving.
// Without a readiness signal an orchestrator sees a healthy process happily
// answering 404 for every business route.
func RegisterReadyRoute(rg *gin.RouterGroup, version string, checks map[string]ReadinessCheck) {
	rg.GET("/readyz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), readinessTimeout)
		defer cancel()

		results := make(map[string]string, len(checks))
		ready := true
		for name, check := range checks {
			if err := check(ctx); err != nil {
				results[name] = "error"
				ready = false
				continue
			}
			results[name] = "ok"
		}

		status := http.StatusOK
		state := "ready"
		if !ready {
			status = http.StatusServiceUnavailable
			state = "not_ready"
		}
		c.JSON(status, ReadinessStatus{Status: state, Version: version, Checks: results})
	})
}
