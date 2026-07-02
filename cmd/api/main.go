package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	port := envOr("API_PORT", "8080")
	version := envOr("APP_VERSION", "dev")
	ginMode := envOr("GIN_MODE", "release")
	gin.SetMode(ginMode)

	engine := httpx.NewEngine(logger)

	// Root group — health check is unauthenticated liveness probe
	root := engine.Group("/")
	httpx.RegisterHealthRoute(root, version)

	// Authenticated API routes live under /api/v1. JWT secrets come from the
	// environment (JWT_ACCESS_SECRET / JWT_REFRESH_SECRET); when they are missing
	// or too short the group is left unwired (fail-closed) instead of falling
	// back to an insecure default. A real login/token-issuance endpoint arrives
	// in a later milestone; until then the group has no routes.
	if authCfg, err := auth.LoadConfigFromEnv(); err == nil {
		if mgr, err := auth.NewManager(authCfg); err == nil {
			api := engine.Group("/api/v1")
			api.Use(auth.RequireAuth(mgr))
			logger.Info("api auth middleware wired", "group", "/api/v1")
		} else {
			logger.Warn("jwt manager init failed; /api/v1 left unwired", "error", err)
		}
	} else {
		logger.Warn("jwt secrets not configured; /api/v1 left unwired", "error", err)
	}

	srv := &http.Server{
		Addr:         net.JoinHostPort("", port),
		Handler:      engine,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("api server starting", "port", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down api server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("api server stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
