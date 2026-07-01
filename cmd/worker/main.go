package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hibiken/asynq"
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

	mux := asynq.NewServeMux()
	// Task handlers are registered here as modules are implemented (M2+).
	// Example: mux.HandleFunc("ingest_scan_result", discovery.HandleIngestScanResult)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		logger.Info("shutting down worker")
		srv.Shutdown()
	}()

	logger.Info("worker starting", "redis", redisAddr)
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
