package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"

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
	// Packages that cannot take a logger (httpx.InternalError) log through the
	// default, so point it at the same structured stream.
	slog.SetDefault(logger)

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
	sqlDB, err := wireAPIRoutes(engine, logger)
	if err != nil {
		logger.Warn("api routes left unwired (fail-closed)", "error", err)
	}

	// Readiness reflects what liveness cannot: whether the business routes are
	// actually wired and the database still answers. An unwired process stays up
	// (so its logs and /healthz remain reachable) but must not receive traffic.
	httpx.RegisterReadyRoute(root, version, readinessChecks(sqlDB))

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

// readinessChecks builds the probe set. A nil db means wiring failed, so the
// "routes" check reports the process as not ready regardless of the database.
func readinessChecks(sqlDB *sql.DB) map[string]httpx.ReadinessCheck {
	return map[string]httpx.ReadinessCheck{
		"routes": func(context.Context) error {
			if sqlDB == nil {
				return errRoutesUnwired
			}
			return nil
		},
		"database": func(ctx context.Context) error {
			if sqlDB == nil {
				return errRoutesUnwired
			}
			return sqlDB.PingContext(ctx)
		},
	}
}

var errRoutesUnwired = errors.New("api routes are not wired")

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

func envBoolOr(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func configuredActiveDispatchPolicy() discovery.ActiveDispatchPolicy {
	defaults := discovery.DefaultActiveDispatchPolicy()
	return discovery.ActiveDispatchPolicy{
		Enabled:          envBoolOr("DISCOVERY_ACTIVE_DISPATCH_ENABLED", defaults.Enabled),
		RequireApproval:  envBoolOr("DISCOVERY_ACTIVE_REQUIRE_APPROVAL", defaults.RequireApproval),
		RequireOwnership: envBoolOr("DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP", defaults.RequireOwnership),
	}
}

// wireAPIRoutes builds the shared platform stack (DB, JWT manager, audit sink,
// Casbin enforcer) and the domain services (auth, project, asset), then
// registers the API routes under /api/v1. Any missing prerequisite — unset/short
// JWT secrets, an unreachable database, or an enforcer that fails to construct —
// returns an error so the caller can leave the routes unwired (fail-closed)
// rather than serving insecurely.
func wireAPIRoutes(engine *gin.Engine, logger *slog.Logger) (*sql.DB, error) {
	authCfg, err := auth.LoadConfigFromEnv()
	if err != nil {
		return nil, err
	}
	mgr, err := auth.NewManager(authCfg)
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.Open(db.LoadConfigFromEnv())
	if err != nil {
		return nil, err
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
		return nil, err
	}
	if err := asmcasbin.SeedMVPolicies(enforcer); err != nil {
		_ = sqlDB.Close()
		return nil, err
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
	projectOpts := []project.ServiceOption{
		project.WithDB(sqlDB),
		project.WithAuditSink(auditSvc),
		project.WithGlobalRoleResolver(userRepo),
	}
	// Domain ownership verification is what turns "authorised to scan" from a
	// self-asserted field into something the platform checked. Without a secret it
	// stays unavailable rather than silently accepting any claim.
	if secret := strings.TrimSpace(os.Getenv("OWNERSHIP_CHALLENGE_SECRET")); len(secret) >= 32 {
		projectOpts = append(projectOpts, project.WithOwnershipVerification([]byte(secret), nil))
	} else {
		logger.Warn("domain ownership verification disabled; set OWNERSHIP_CHALLENGE_SECRET (>=32 bytes)")
	}
	projectSvc := project.NewService(
		project.NewRepository(queries),
		enforcer,
		projectOpts...,
	)
	assetSvc := asset.NewService(
		asset.NewRepository(queries),
		asset.WithDB(sqlDB),
		asset.WithRelationRepository(asset.NewRelationRepository(queries)),
		asset.WithMissThreshold(envIntOr("ASSET_MISS_THRESHOLD", asset.DefaultMissThreshold)),
	)
	discoveryOpts := []discovery.ServiceOption{
		discovery.WithDB(sqlDB),
		discovery.WithAuditSink(auditSvc),
		// The checker is always available; ActiveDispatchPolicy decides whether
		// verified-domain ownership is required for this deployment.
		discovery.WithOwnershipChecker(projectSvc),
	}
	activePolicy := configuredActiveDispatchPolicy()
	discoveryOpts = append(discoveryOpts, discovery.WithActiveDispatchPolicy(activePolicy))
	logger.Info(
		"active discovery dispatch policy",
		"enabled", activePolicy.Enabled,
		"require_approval", activePolicy.RequireApproval,
		"require_ownership", activePolicy.RequireOwnership,
	)
	engineConfig := configuredDiscoveryEngineConfig()
	engineSettings, settingsErr := discovery.OpenEngineSettings(context.Background(), sqlDB, discovery.SettingsFromEnvironment(engineConfig, activePolicy))
	if settingsErr != nil {
		return nil, settingsErr
	}
	discoveryOpts = append(discoveryOpts, discovery.WithEngineSettings(engineSettings))
	engineRouter, engineStatus := discovery.NewConfiguredEngineRouter(engineConfig, nil, nil)
	logDiscoveryEngineStatus(logger, engineStatus)
	if engineStatus.Passive.Configured || engineStatus.Active.Configured {
		discoveryOpts = append(discoveryOpts, discovery.WithEngineRouter(engineRouter))
	}
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
		// Without a sender the service recorded deliveries and sent nothing. The
		// webhook transport goes through the SSRF-guarded client; email has no
		// transport yet, so that channel fails loudly instead of silently.
		notification.WithSender(notification.NewChannelRouter(map[string]notification.Sender{
			notification.ChannelWebhook: notification.NewWebhookSender(),
		})),
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
	callbackSecret := strings.TrimSpace(os.Getenv("DISCOVERY_CALLBACK_SECRET"))
	callbackLegacySecret := strings.TrimSpace(os.Getenv("DISCOVERY_CALLBACK_LEGACY_SECRET"))
	callbackSecretsJSON := strings.TrimSpace(os.Getenv("DISCOVERY_CALLBACK_SECRETS"))
	callbackSecretRef := strings.TrimSpace(os.Getenv("DISCOVERY_CALLBACK_SECRET_REF"))
	callbackBaseURL := strings.TrimSpace(os.Getenv("DISCOVERY_CALLBACK_BASE_URL"))
	callbackConfigured := callbackSecret != "" || callbackSecretsJSON != ""
	var callbackCredentials *discovery.CallbackCredentialSet
	if callbackConfigured {
		if callbackLegacySecret == "" {
			callbackLegacySecret = callbackSecret
		}
		callbackCredentials, err = discovery.NewCallbackCredentialSet(callbackSecretRef, callbackLegacySecret, callbackSecretsJSON)
		if err != nil {
			return nil, err
		}
		discoveryOpts = append(discoveryOpts,
			discovery.WithCallbackEnqueuer(discovery.NewAsynqCallbackEnqueuer(asynqClient, "default")),
			discovery.WithCallbackSecretRef(callbackCredentials.ActiveRef()),
		)
	}
	if callbackConfigured && callbackBaseURL != "" {
		if _, err := discovery.NewCallbackURLBuilder(callbackBaseURL); err == nil {
			discoveryOpts = append(discoveryOpts,
				discovery.WithDispatchEnqueuer(discovery.NewAsynqDispatchEnqueuer(asynqClient, "default")),
			)
		} else {
			logger.Warn("discovery trigger disabled; invalid callback base URL", "env", "DISCOVERY_CALLBACK_BASE_URL")
		}
	} else {
		logger.Warn("discovery trigger disabled; callback configuration incomplete")
	}
	discoverySvc := discovery.NewService(discovery.NewRepository(queries), discoveryOpts...)
	engineRuntimeStore := discovery.NewRedisEngineRuntimeStore(redis.NewClient(&redis.Options{
		Addr: redisAddr, Password: redisPassword,
	}))
	engineManagementSvc := discovery.NewEngineManagementService(
		engineConfig, engineStatus, engineRouter, activePolicy, userRepo, auditSvc, engineRuntimeStore,
	).WithSettings(engineSettings)

	// Split /api/v1 into public (login, refresh) and protected (everything
	// else) groups. Business routes added to apiProtected automatically get
	// RequireAuth — no route can accidentally skip authentication.
	//
	// The two unauthenticated groups are throttled separately: login/refresh get a
	// tight per-address bucket against credential stuffing, while the engine
	// callback gets a far looser one, since a single scan run legitimately posts
	// many callbacks and only the audit-write amplification needs bounding.
	api := engine.Group("/api/v1")
	apiAuthPublic := api.Group("")
	apiAuthPublic.Use(httpx.RateLimitByIP(httpx.LoginRateLimitConfig()))
	apiCallbackPublic := api.Group("")
	apiCallbackPublic.Use(httpx.RateLimitByIP(httpx.CallbackRateLimitConfig()))
	apiAuthenticated := api.Group("")
	apiAuthenticated.Use(auth.RequireAuth(mgr, userRepo))
	apiProtected := api.Group("")
	apiProtected.Use(auth.RequireAuth(mgr, userRepo), auth.RequirePasswordChanged())

	auth.NewHandler(authSvc).RegisterRoutes(apiAuthPublic, apiAuthenticated)
	auth.NewAdminUserHandler(adminUserSvc).RegisterRoutes(apiProtected)
	project.NewHandler(projectSvc, enforcer).RegisterRoutes(apiProtected)
	discovery.NewManagementHandler(discoverySvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	discovery.NewEngineManagementHandler(engineManagementSvc).RegisterRoutes(apiProtected)
	if callbackCredentials != nil {
		callbackHandler, handlerErr := discovery.NewCredentialBoundHandler(discoverySvc, callbackCredentials, logger)
		if handlerErr != nil {
			return nil, handlerErr
		}
		callbackHandler.RegisterPublicRoutes(apiCallbackPublic)
	} else {
		logger.Warn("discovery callback route not wired; callback credentials are unset")
	}
	asset.NewHandler(assetSvc, projectSvc, enforcer, logger).RegisterRoutes(apiProtected)
	exposure.NewHandler(exposureSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	risk.NewHandler(riskSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	ticket.NewHandler(ticketSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	notification.NewHandler(notificationSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	report.NewHandler(reportSvc, projectSvc, enforcer).RegisterRoutes(apiProtected)
	logger.Info("api routes wired", "group", "/api/v1")
	return sqlDB, nil
}

func configuredDiscoveryEngineRouter() (*discovery.TaskTypeEngineRouter, discovery.EngineRouterConfigStatus) {
	return discovery.NewConfiguredEngineRouter(configuredDiscoveryEngineConfig(), nil, nil)
}

func configuredDiscoveryEngineConfig() discovery.EngineRouterConfig {
	return discovery.EngineRouterConfig{
		// Keep the old names as a compatibility fallback while deployments move
		// to explicit passive/active configuration.
		PassiveBaseURL: envOr("DISCOVERY_PASSIVE_ENGINE_BASE_URL", os.Getenv("DISCOVERY_ENGINE_BASE_URL")),
		PassiveToken:   envOr("DISCOVERY_PASSIVE_ENGINE_TOKEN", os.Getenv("DISCOVERY_ENGINE_TOKEN")),
		ActiveBaseURL:  strings.TrimSpace(os.Getenv("DISCOVERY_ACTIVE_ENGINE_BASE_URL")),
		ActiveAccessKey: strings.TrimSpace(
			os.Getenv("DISCOVERY_ACTIVE_ENGINE_ACCESS_KEY"),
		),
		ActiveSecretKey:  os.Getenv("DISCOVERY_ACTIVE_ENGINE_SECRET_KEY"),
		ActiveProjectMap: strings.TrimSpace(os.Getenv("DISCOVERY_ACTIVE_ENGINE_PROJECT_MAP")),
	}
}

func logDiscoveryEngineStatus(logger *slog.Logger, status discovery.EngineRouterConfigStatus) {
	switch {
	case status.Passive.Ready:
		logger.Info("passive discovery engine configured", "route", discovery.EngineRoutePassive)
	case status.Passive.Err != nil:
		logger.Warn("passive discovery engine disabled", "error", status.Passive.Err)
	default:
		logger.Warn("passive discovery engine disabled; configuration is unset")
	}
	switch {
	case status.Active.Ready:
		logger.Info("active discovery engine configured", "route", discovery.EngineRouteActive)
	case status.Active.Err != nil:
		logger.Warn("active discovery engine disabled", "error", status.Active.Err)
	default:
		logger.Info("active discovery engine not configured")
	}
}
