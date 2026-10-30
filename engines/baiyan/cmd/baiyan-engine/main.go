package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"baiyan/internal/capability"
	"baiyan/internal/engine"
	"baiyan/internal/job"
	"baiyan/internal/networkenrich"
	"baiyan/internal/toolrunner"
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
	// BAIYAN_DNS_RESOLVERS lists upstream DNS servers ("ip" or "ip:port",
	// comma separated) queried directly with failover. Unset, lookups use the
	// system resolver and retry a failed lookup once.
	dnsResolver, err := networkenrich.NewFailoverResolver(strings.Split(os.Getenv("BAIYAN_DNS_RESOLVERS"), ","))
	if err != nil {
		logger.Error("invalid DNS resolver configuration", "error", err)
		os.Exit(1)
	}
	var resolver capability.Resolver = capability.NewNetResolver(dnsResolver, capability.DNSLookupTimeout)
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
	passiveExecutor := capability.NewPassiveExecutor(providers, resolver, checkpointedSender)

	// External tools are opt-in. A deployment that does not set the tool
	// directory registers nothing, and org_intel then reports itself as
	// unconfigured instead of silently returning no results.
	toolRegistry, err := buildToolRegistry(envOr("BAIYAN_TOOL_DIR", "/app/tools"))
	if err != nil {
		logger.Error("external tool registration failed", "error", err)
		os.Exit(1)
	}
	orgIntelExecutor := capability.NewOrgIntelExecutor(
		toolRegistry, checkpointedSender, envOr("BAIYAN_TOOL_WORK_DIR", os.TempDir()),
	)
	// One executor serves both passive job types today. Registering them
	// separately is what lets a new capability be added without any job type
	// silently falling through to passive collection.
	router, err := capability.NewRouter(map[string]job.Executor{
		"passive_intel": passiveExecutor,
		"dns":           passiveExecutor,
		"org_intel":     orgIntelExecutor,
	})
	if err != nil {
		logger.Error("engine capability routing invalid", "error", err)
		os.Exit(1)
	}
	configurationManager, err := engine.NewConfigurationManager(
		envOr("BAIYAN_CONFIGURATION_DIR", filepath.Join(envOr("BAIYAN_JOB_STORE_DIR", "/var/lib/baiyan/jobs"), ".configuration")),
		engine.ProviderConfiguration{FOFAEnabled: fofaEmail != "" && fofaKey != "", FOFAEmail: fofaEmail, FOFAKey: fofaKey, FOFAMaxResults: envIntOr("FOFA_MAX_RESULTS", 1000), PassiveName: envOr("BAIYAN_PASSIVE_PROVIDER_NAME", "certificate_transparency"), PassiveURL: os.Getenv("BAIYAN_PASSIVE_PROVIDER_URL"), PassiveToken: os.Getenv("BAIYAN_PASSIVE_PROVIDER_TOKEN"), PassiveMaxResults: envIntOr("BAIYAN_PASSIVE_MAX_RESULTS", 500), DNSURL: os.Getenv("BAIYAN_DNS_PROVIDER_URL"), DNSToken: os.Getenv("BAIYAN_DNS_PROVIDER_TOKEN"), DNSMaxResults: envIntOr("BAIYAN_DNS_MAX_RESULTS", 500)}, router, checkpointedSender)
	if err != nil {
		logger.Error("engine configuration storage unavailable")
		os.Exit(1)
	}
	configurationManager.WithTools(toolRegistry)
	configurationManager.WithDNSResolver(dnsResolver)
	jobs := job.NewService(store, configurationManager, envIntOr("BAIYAN_QUEUE_SIZE", 100))
	if err := jobs.Start(envIntOr("BAIYAN_WORKERS", 2)); err != nil {
		logger.Error("job service failed to start", "error", err)
		os.Exit(1)
	}
	defer jobs.Shutdown()
	handler, err := engine.NewHandlerWithManagement(
		jobs, os.Getenv("BAIYAN_ENGINE_TOKEN"), os.Getenv("BAIYAN_CALLBACK_ALLOWED_ORIGIN"),
		engine.ManagementConfig{
			EngineID:     os.Getenv("BAIYAN_ENGINE_ID"),
			Capabilities: router.SupportedJobTypes(),
			Providers: []engine.ManagementProviderConfig{
				{
					Key: "fofa", Name: "FOFA", Configured: strings.TrimSpace(fofaEmail) != "" && strings.TrimSpace(fofaKey) != "",
					Credentials: []engine.ManagementCredentialConfig{
						{Key: "email", Kind: engine.CredentialKindEmail, Value: fofaEmail},
						{Key: "key", Kind: engine.CredentialKindSecret, Value: fofaKey},
					},
				},
			},
		},
	)
	if err != nil {
		logger.Error("engine HTTP configuration invalid", "error", err)
		os.Exit(1)
	}
	handler.WithConfigurations(configurationManager)
	handler.WithNetworkResolver(dnsResolver)
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
	logger.Info("baiyan engine starting", "listen", server.Addr,
		"providers", len(providers), "job_types", router.SupportedJobTypes(), "dns_upstreams", dnsResolver.Upstreams(),
		"tools", toolRegistry.Names())
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

// buildToolRegistry registers the external binaries this engine may execute.
//
// An empty directory is a valid configuration — it means no external tools — but
// a directory that is set and missing its tools is a broken deployment and must
// stop the engine rather than quietly disable a capability.
func buildToolRegistry(toolDir string) (*toolrunner.Registry, error) {
	if strings.TrimSpace(toolDir) == "" {
		return toolrunner.NewRegistry(nil)
	}
	specs := make([]toolrunner.Spec, 0, 2)
	subfinderPath := filepath.Join(toolDir, "subfinder")
	if _, err := os.Stat(subfinderPath); err == nil {
		specs = append(specs, capability.SubfinderToolSpec(subfinderPath))
	}
	enscanPath := filepath.Join(toolDir, "enscan")
	if _, err := os.Stat(enscanPath); err == nil {
		specs = append(specs, capability.EnscanToolSpec(enscanPath))
	}
	return toolrunner.NewRegistry(specs)
}
