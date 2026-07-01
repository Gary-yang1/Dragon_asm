package httpx

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HealthStatus is the health check response body.
type HealthStatus struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// RegisterHealthRoute mounts GET /healthz on the given router group.
func RegisterHealthRoute(rg *gin.RouterGroup, version string) {
	rg.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, HealthStatus{
			Status:  "ok",
			Version: version,
		})
	})
}
