package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"baiyan/internal/capability"
	"baiyan/internal/engine"
	"baiyan/internal/job"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	callbackSender, err := engine.NewIdentityBoundCallbackSender(
		os.Getenv("BAIYAN_CALLBACK_SECRET"),
		os.Getenv("BAIYAN_ENGINE_ID"),
		os.Getenv("BAIYAN_CALLBACK_ALLOWED_ORIGIN"),
		&http.Client{Timeout: 15 * time.Second},
	)
	if err != nil {
		logger.Error("invalid callback configuration", "error", err)
		os.Exit(1)
	}
	store, err := job.NewFileStore(envOr("BAIYAN_JOB_STORE_DIR", "/var/lib/baiyan/jobs"))
	if err != nil {
		logger.Error("job store unavailable", "error", err)
		os.Exit(1)
	}
	checkpointedSender, err := capability.NewCheckpointedBatchSender(store, callbackSender)
	if err != nil {
		logger.Error("callback checkpoint unavailable", "error", err)
		os.Exit(1)
	}
	providers := make([]capability.PassiveProvider, 0, 2)
	fofaEmail := os.Getenv("FOFA_EMAIL")
	fofaKey := os.Getenv("FOFA_KEY")
	if fofaEmail != "" || fofaKey != "" {
		provider, err := capability.NewFOFAPassiveProvider(
			fofaEmail, fofaKey, "", &http.Client{Timeout: 20 * time.Second}, envIntOr("FOFA_MAX_RESULTS", 1000),
		)
		if err != nil {
			logger.Error("invalid FOFA provider configuration", "error", err)
			os.Exit(1)
		}
		providers = append(providers, provider)
	}
	if baseURL := os.Getenv("BAIYAN_PASSIVE_PROVIDER_URL"); baseURL != "" {
		provider, err := capability.NewHTTPPassiveProvider(
			envOr("BAIYAN_PASSIVE_PROVIDER_NAME", "certificate_transparency"), baseURL,
			os.Getenv("BAIYAN_PASSIVE_PROVIDER_TOKEN"), &http.Client{Timeout: 15 * time.Second},
			envIntOr("BAIYAN_PASSIVE_MAX_RESULTS", 500),
		)
		if err != nil {
			logger.Error("invalid passive provider configuration", "error", err)
			os.Exit(1)
		}
		providers = append(providers, provider)
	}
	var resolver capability.Resolver = capability.NewNetResolver(nil, 5*time.Second)
	if resolverURL := os.Getenv("BAIYAN_DNS_PROVIDER_URL"); resolverURL != "" {
		resolver, err = capability.NewHTTPResolver(
			resolverURL, os.Getenv("BAIYAN_DNS_PROVIDER_TOKEN"), &http.Client{Timeout: 10 * time.Second},
			envIntOr("BAIYAN_DNS_MAX_RESULTS", 500),
		)
		if err != nil {
			logger.Error("invalid DNS provider configuration", "error", err)
			os.Exit(1)
		}
	}
	executor := capability.NewPassiveExecutor(providers, resolver, checkpointedSender)
	jobs := job.NewService(store, executor, envIntOr("BAIYAN_QUEUE_SIZE", 100))
	if err := jobs.Start(envIntOr("BAIYAN_WORKERS", 2)); err != nil {
		logger.Error("job service failed to start", "error", err)
		os.Exit(1)
	}
	defer jobs.Shutdown()
	handler, err := engine.NewHandler(jobs, os.Getenv("BAIYAN_ENGINE_TOKEN"), os.Getenv("BAIYAN_CALLBACK_ALLOWED_ORIGIN"))
	if err != nil {
		logger.Error("engine HTTP configuration invalid", "error", err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr: envOr("BAIYAN_LISTEN_ADDR", ":9090"), Handler: handler.Routes(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	logger.Info("baiyan passive engine starting", "listen", server.Addr, "providers", len(providers))
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("engine server failed", "error", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
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
