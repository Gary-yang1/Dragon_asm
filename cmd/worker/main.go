package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	"github.com/Gary-yang1/Dragon_asm/internal/discovery"
	"github.com/Gary-yang1/Dragon_asm/internal/exposure"
	"github.com/Gary-yang1/Dragon_asm/internal/notification"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/db"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/retention"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
	"github.com/Gary-yang1/Dragon_asm/internal/report"
	"github.com/Gary-yang1/Dragon_asm/internal/risk"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	// Packages that cannot take a logger (httpx.InternalError) log through the
	// default, so point it at the same structured stream.
	slog.SetDefault(logger)

	redisAddr := envOr("REDIS_ADDR", "localhost:6379")
	redisPassword := os.Getenv("REDIS_PASSWORD")

	redisOpt := asynq.RedisClientOpt{
		Addr:     redisAddr,
		Password: redisPassword,
	}
	queueClient := asynq.NewClient(redisOpt)
	defer func() {
		if err := queueClient.Close(); err != nil {
			logger.Warn("redis queue client close failed", "error", err)
		}
	}()

	// Worker concurrency — each queue gets its own worker budget.
	// Queues added here as tasks are implemented in later milestones.
	srv := asynq.NewServer(
		redisOpt,
		asynq.Config{
			Concurrency: 10,
			Queues: map[string]int{
				"critical": 6,
				"default":  3,
				"low":      1,
			},
			Logger: &asynqLogger{logger},
		},
	)
	scheduler := asynq.NewScheduler(redisOpt, &asynq.SchedulerOpts{Logger: &asynqLogger{logger}})
	entries, err := discovery.RegisterPeriodicTasks(scheduler, "default")
	if err != nil {
		logger.Error("discovery periodic task registration failed", "error", err)
		os.Exit(1)
	}
	// Retention had a complete service and no scheduler, so the archive/prune job
	// never ran and the audit, change-event and callback tables grew unbounded.
	retentionEntries, err := retention.RegisterPeriodicTasks(scheduler, "low")
	if err != nil {
		logger.Error("retention periodic task registration failed", "error", err)
		os.Exit(1)
	}
	entries = append(entries, retentionEntries...)
	enrichmentEntry, err := discovery.RegisterNetworkEnrichmentTask(scheduler, "low")
	if err != nil {
		logger.Error("network enrichment registration failed", "error", err)
		os.Exit(1)
	}
	entries = append(entries, enrichmentEntry)

	sqlDB, err := db.Open(db.LoadConfigFromEnv())
	if err != nil {
		logger.Error("database unavailable", "error", err)
		os.Exit(1)
	}
	queries := dbgen.New(sqlDB)
	auditSvc := audit.NewService(audit.NewRepository(queries))
	assetSvc := asset.NewService(asset.NewRepository(queries), asset.WithDB(sqlDB))
	riskSvc := risk.NewService(risk.NewRepository(queries), risk.WithDB(sqlDB))
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
		report.WithAuditSink(auditSvc),
		report.WithExportDir(envOr("REPORT_EXPORT_DIR", "/tmp/asm-report-exports")),
	)
	discoveryOpts := []discovery.ServiceOption{
		discovery.WithDB(sqlDB),
		discovery.WithAuditSink(auditSvc),
		// The worker is where dispatch happens. The checker is always wired;
		// ActiveDispatchPolicy decides whether this deployment requires it.
		discovery.WithOwnershipChecker(project.NewService(
			project.NewRepository(queries), nil, project.WithDB(sqlDB),
		)),
		discovery.WithCallbackEnqueuer(discovery.NewAsynqCallbackEnqueuer(queueClient, "default")),
		discovery.WithAssetMissThreshold(envIntOr("ASSET_MISS_THRESHOLD", asset.DefaultMissThreshold)),
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
		logger.Error("engine configuration storage unavailable")
		os.Exit(1)
	}
	discoveryOpts = append(discoveryOpts, discovery.WithEngineSettings(engineSettings))
	engineRouter, engineStatus := discovery.NewConfiguredEngineRouter(engineConfig, nil, nil)
	logDiscoveryEngineStatus(logger, engineStatus)
	if engineStatus.Passive.Configured || engineStatus.Active.Configured {
		discoveryOpts = append(discoveryOpts, discovery.WithEngineRouter(engineRouter))
	}
	discoveryRepo := discovery.NewRepository(queries)
	discoverySvc := discovery.NewService(discoveryRepo, discoveryOpts...)
	engineRuntimeClient := redis.NewClient(&redis.Options{Addr: redisAddr, Password: redisPassword})
	defer func() {
		if err := engineRuntimeClient.Close(); err != nil {
			logger.Warn("engine runtime redis close failed", "error", err)
		}
	}()
	heartbeatCtx, stopHeartbeat := context.WithCancel(context.Background())
	defer stopHeartbeat()
	go publishEngineRuntimeHeartbeat(
		heartbeatCtx,
		discovery.NewRedisEngineRuntimeStore(engineRuntimeClient),
		discovery.EngineRuntimeConfigFingerprint(engineConfig, activePolicy),
		logger, engineSettings,
	)
	callbackBuilder, callbackErr := discovery.NewCallbackURLBuilder(os.Getenv("DISCOVERY_CALLBACK_BASE_URL"))
	if callbackErr != nil {
		logger.Warn("discovery dispatch disabled; callback base URL not configured", "env", "DISCOVERY_CALLBACK_BASE_URL")
	}

	mux := asynq.NewServeMux()
	discovery.NewDispatchHandler(discoverySvc, callbackBuilder, logger).Register(mux)
	discovery.NewIngestHandler(assetSvc, logger).WithCallbackInbox(discoverySvc).WithCallbackFactIngester(discoverySvc).WithExposureIngester(exposureSvc).Register(mux)
	discovery.NewRecoverCallbacksHandler(discoverySvc, logger).Register(mux)
	discovery.NewReconcileHandler(discoverySvc, logger).Register(mux)
	discovery.NewNetworkEnrichmentHandler(discoverySvc, logger).Register(mux)
	report.NewExportHandler(reportSvc, logger).Register(mux)
	retention.NewHandler(retention.NewService(sqlDB), logger).Register(mux)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	if err := scheduler.Start(); err != nil {
		logger.Error("worker scheduler failed to start", "error", err)
		os.Exit(1)
	}
	defer scheduler.Shutdown()

	go func() {
		<-quit
		logger.Info("shutting down worker")
		stopHeartbeat()
		scheduler.Shutdown()
		srv.Shutdown()
	}()

	logger.Info("worker starting", "redis", redisAddr, "periodic_entries", len(entries))
	if err := srv.Run(mux); err != nil {
		logger.Error("worker failed", "error", err)
		os.Exit(1)
	}
	logger.Info("worker stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
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

func publishEngineRuntimeHeartbeat(
	ctx context.Context,
	store *discovery.RedisEngineRuntimeStore,
	fingerprint string,
	logger *slog.Logger,
	settings ...*discovery.EngineSettingsStore,
) {
	publish := func() {
		status := discovery.WorkerEngineRuntimeStatus{
			ConfigFingerprint: fingerprint,
			UpdatedAt:         time.Now().UTC(),
		}
		if len(settings) > 0 && settings[0] != nil {
			readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			snapshot, err := settings[0].Latest(readCtx)
			cancel()
			if err != nil {
				logger.Warn("worker could not load engine configuration")
				return
			}
			status.ConfigurationVersion = snapshot.Version
			status.ConfigFingerprint = discovery.EngineRuntimeConfigFingerprint(snapshot.Settings.RouterConfig(), snapshot.Settings.Policy)
		}
		if err := store.WriteWorkerEngineStatus(ctx, status); err != nil && ctx.Err() == nil {
			logger.Warn("worker engine heartbeat failed", "error", err)
		}
	}
	publish()
	ticker := time.NewTicker(discovery.WorkerEngineHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publish()
		}
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

// asynqLogger adapts slog to asynq's Logger interface.
// asynq passes plain print-style messages as args (e.g. Info("Scheduler starting")),
// so we collapse them into a single message string with fmt.Sprint rather than
// feeding them to slog as (broken) key-value attributes.
type asynqLogger struct{ l *slog.Logger }

func (a *asynqLogger) Debug(args ...any) { a.l.Debug(fmt.Sprint(args...)) }
func (a *asynqLogger) Info(args ...any)  { a.l.Info(fmt.Sprint(args...)) }
func (a *asynqLogger) Warn(args ...any)  { a.l.Warn(fmt.Sprint(args...)) }
func (a *asynqLogger) Error(args ...any) { a.l.Error(fmt.Sprint(args...)) }
func (a *asynqLogger) Fatal(args ...any) {
	a.l.Error(fmt.Sprint(args...))
	os.Exit(1)
}
