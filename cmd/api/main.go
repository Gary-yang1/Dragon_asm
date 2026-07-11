package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/discovery"
	"github.com/Gary-yang1/Dragon_asm/internal/exposure"
	"github.com/Gary-yang1/Dragon_asm/internal/notification"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/db"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
	"github.com/Gary-yang1/Dragon_asm/internal/report"
	"github.com/Gary-yang1/Dragon_asm/internal/risk"
	"github.com/Gary-yang1/Dragon_asm/internal/ticket"
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

// envIntOr reads an integer env var, falling back to fallback when unset or
// non-numeric. A non-positive value also falls back (defensive: a 0/negative
// threshold would never trigger).
func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
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
	redisAddr := envOr("REDIS_ADDR", "localhost:6379")
	redisPassword := os.Getenv("REDIS_PASSWORD")
	asynqClient := asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr, Password: redisPassword})

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
	authSvc := auth.NewService(userRepo, mgr, enforcer, auditSvc, auth.WithAuthDB(sqlDB))
	adminUserSvc := auth.NewAdminUserService(
		auth.NewAdminUserRepository(queries),
		userRepo,
		auth.WithAdminUserDB(sqlDB),
		auth.WithAdminUserAuditSink(auditSvc),
	)
	projectSvc := project.NewService(
		project.NewRepository(queries),
		enforcer,
		project.WithDB(sqlDB),
		project.WithAuditSink(auditSvc),
		project.WithGlobalRoleResolver(userRepo),
	)
	assetSvc := asset.NewService(
		asset.NewRepository(queries),
		asset.WithDB(sqlDB),
		asset.WithRelationRepository(asset.NewRelationRepository(queries)),
		asset.WithMissThreshold(envIntOr("ASSET_MISS_THRESHOLD", asset.DefaultMissThreshold)),
	)
	discoverySvc := discovery.NewService(
		discovery.NewRepository(queries),
		discovery.WithDB(sqlDB),
		discovery.WithAuditSink(auditSvc),
	)
	riskSvc := risk.NewService(risk.NewRepository(queries), risk.WithDB(sqlDB))
	ticketSvc := ticket.NewService(
		ticket.NewRepository(queries),
		ticket.WithDB(sqlDB),
		ticket.WithRiskService(riskSvc),
		ticket.WithAuditSink(auditSvc),
	)
	notificationSvc := notification.NewService(
		notification.NewRepository(queries),
		notification.WithDB(sqlDB),
		notification.WithAuditSink(auditSvc),
	)
	exposureSvc := exposure.NewService(
		exposure.NewRepository(queries),
		exposure.WithCertificateRiskReporter(riskSvc),
		exposure.WithNotificationTrigger(notificationSvc),
	)
	reportSvc := report.NewService(
		report.NewRepository(queries),
		report.WithDB(sqlDB),
		report.WithAuditSink(auditSvc),
		report.WithExportDir(envOr("REPORT_EXPORT_DIR", "/tmp/asm-report-exports")),
		report.WithExportEnqueuer(report.NewAsynqExportEnqueuer(asynqClient, "low")),
	)
	callbackSecret := os.Getenv("DISCOVERY_CALLBACK_SECRET")
	if callbackSecret != "" {
		discoverySvc = discovery.NewService(
			discovery.NewRepository(queries),
			discovery.WithDB(sqlDB),
			discovery.WithAuditSink(auditSvc),
			discovery.WithCallbackEnqueuer(discovery.NewAsynqCallbackEnqueuer(asynqClient, "default")),
		)
	}

	// Split /api/v1 into public (login, refresh) and protected (everything
	// else) groups. Business routes added to apiProtected automatically get
	// RequireAuth — no route can accidentally skip authentication.
	api := engine.Group("/api/v1")
	apiPublic := api.Group("")
	apiAuthenticated := api.Group("")
	apiAuthenticated.Use(auth.RequireAuth(mgr, userRepo))
	apiProtected := api.Group("")
	apiProtected.Use(auth.RequireAuth(mgr, userRepo), auth.RequirePasswordChanged())

	auth.NewHandler(authSvc).RegisterRoutes(apiPublic, apiAuthenticated)
	auth.NewAdminUserHandler(adminUserSvc).RegisterRoutes(apiProtected)
	project.NewHandler(projectSvc, enforcer).RegisterRoutes(apiProtected)
	if callbackSecret != "" {
		discovery.NewHandler(discoverySvc, callbackSecret, logger).RegisterPublicRoutes(apiPublic)
	} else {
		logger.Warn("discovery callback route not wired; DISCOVERY_CALLBACK_SECRET is unset")
	}
	asset.NewHandler(assetSvc, projectSvc, enforcer, logger).RegisterRoutes(apiProtected)
	exposure.NewHandler(exposureSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	risk.NewHandler(riskSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	ticket.NewHandler(ticketSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	notification.NewHandler(notificationSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	report.NewHandler(reportSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	logger.Info("api routes wired", "group", "/api/v1")
	return nil
}
