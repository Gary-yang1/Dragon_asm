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

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/db"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
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
	// or too short — or the database is unreachable — the business routes are
	// left unwired (fail-closed) instead of falling back to an insecure default.
	if err := wireAPIRoutes(engine, logger); err != nil {
		logger.Warn("api routes left unwired (fail-closed)", "error", err)
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

// wireAPIRoutes builds the shared platform stack (DB, JWT manager, audit sink,
// Casbin enforcer) and the domain services (auth, project, asset), then
// registers the API routes under /api/v1. Any missing prerequisite — unset/short
// JWT secrets, an unreachable database, or an enforcer that fails to construct —
// returns an error so the caller can leave the routes unwired (fail-closed)
// rather than serving insecurely.
func wireAPIRoutes(engine *gin.Engine, logger *slog.Logger) error {
	authCfg, err := auth.LoadConfigFromEnv()
	if err != nil {
		return err
	}
	mgr, err := auth.NewManager(authCfg)
	if err != nil {
		return err
	}

	sqlDB, err := db.Open(db.LoadConfigFromEnv())
	if err != nil {
		return err
	}
	queries := dbgen.New(sqlDB)

	// The Casbin policy store is wired in a later milestone; construct an
	// adapterless enforcer and seed the MVP role→permission matrix in memory so
	// action-permission checks (asset:read / asset:write / …) are usable in
	// production. Without the seed, every business route would 403 even for
	// project members. Project access still works via project_member rows.
	enforcer, err := asmcasbin.NewEnforcer(nil)
	if err != nil {
		_ = sqlDB.Close()
		return err
	}
	if err := asmcasbin.SeedMVPolicies(enforcer); err != nil {
		_ = sqlDB.Close()
		return err
	}

	auditSvc := audit.NewService(audit.NewRepository(queries))

	// Domain services share the same queries and enforcer. The asset service is
	// given the *sql.DB so its mutating operations run the asset write and the
	// audit event in one transaction (commit together, or roll back together).
	userRepo := auth.NewUserRepository(queries)
	authSvc := auth.NewService(userRepo, mgr, enforcer, auditSvc)
	projectSvc := project.NewService(project.NewRepository(queries), enforcer)
	assetSvc := asset.NewService(asset.NewRepository(queries), asset.WithDB(sqlDB))

	// Split /api/v1 into public (login, refresh) and protected (everything
	// else) groups. Business routes added to apiProtected automatically get
	// RequireAuth — no route can accidentally skip authentication.
	api := engine.Group("/api/v1")
	apiPublic := api.Group("")
	apiProtected := api.Group("")
	apiProtected.Use(auth.RequireAuth(mgr))

	auth.NewHandler(authSvc).RegisterRoutes(apiPublic, apiProtected)
	asset.NewHandler(assetSvc, projectSvc, enforcer, logger).RegisterRoutes(apiProtected)
	logger.Info("api routes wired", "group", "/api/v1")
	return nil
}
