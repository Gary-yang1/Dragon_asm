package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/hibiken/asynq"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	"github.com/Gary-yang1/Dragon_asm/internal/discovery"
	"github.com/Gary-yang1/Dragon_asm/internal/exposure"
	"github.com/Gary-yang1/Dragon_asm/internal/notification"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/db"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/Gary-yang1/Dragon_asm/internal/report"
	"github.com/Gary-yang1/Dragon_asm/internal/risk"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

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
		discovery.WithCallbackEnqueuer(discovery.NewAsynqCallbackEnqueuer(queueClient, "default")),
		discovery.WithAssetMissThreshold(envIntOr("ASSET_MISS_THRESHOLD", asset.DefaultMissThreshold)),
	}
	if engineURL := os.Getenv("DISCOVERY_ENGINE_BASE_URL"); engineURL != "" {
		engine, err := discovery.NewHTTPEngineAdapter(engineURL, os.Getenv("DISCOVERY_ENGINE_TOKEN"), nil)
		if err != nil {
			logger.Warn("discovery dispatch disabled; invalid engine configuration", "error", err)
		} else {
			discoveryOpts = append(discoveryOpts, discovery.WithEngineAdapter(engine))
		}
	} else {
		logger.Warn("discovery dispatch disabled; engine not configured", "env", "DISCOVERY_ENGINE_BASE_URL")
	}
	discoveryRepo := discovery.NewRepository(queries)
	discoverySvc := discovery.NewService(discoveryRepo, discoveryOpts...)
	callbackBuilder, callbackErr := discovery.NewCallbackURLBuilder(os.Getenv("DISCOVERY_CALLBACK_BASE_URL"))
	if callbackErr != nil {
		logger.Warn("discovery dispatch disabled; callback base URL not configured", "env", "DISCOVERY_CALLBACK_BASE_URL")
	}

	mux := asynq.NewServeMux()
	discovery.NewDispatchHandler(discoverySvc, callbackBuilder, logger).Register(mux)
	discovery.NewIngestHandler(assetSvc, logger).WithCallbackInbox(discoverySvc).WithCallbackFactIngester(discoverySvc).WithExposureIngester(exposureSvc).Register(mux)
	discovery.NewRecoverCallbacksHandler(discoverySvc, logger).Register(mux)
	discovery.NewReconcileHandler(discoverySvc, logger).Register(mux)
	report.NewExportHandler(reportSvc, logger).Register(mux)

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
