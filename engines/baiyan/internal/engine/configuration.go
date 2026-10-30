package engine

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"baiyan/internal/capability"
	"baiyan/internal/contract"
	"baiyan/internal/job"
	"baiyan/internal/networkenrich"
	"baiyan/internal/toolrunner"
)

var errRuntimeConfiguration = errors.New("engine configuration unavailable or invalid")

type ProviderConfiguration struct {
	SubfinderDisabled bool   `json:"subfinder_disabled"`
	QuakeEnabled      bool   `json:"quake_enabled"`
	QuakeKey          string `json:"quake_key"`
	HunterEnabled     bool   `json:"hunter_enabled"`
	HunterKey         string `json:"hunter_key"`
	FOFAEnabled       bool   `json:"fofa_enabled"`
	FOFAEmail         string `json:"fofa_email"`
	FOFAKey           string `json:"fofa_key"`
	FOFAMaxResults    int    `json:"fofa_max_results"`
	PassiveName       string `json:"provider_name"`
	PassiveURL        string `json:"provider_url"`
	PassiveToken      string `json:"provider_token"`
	PassiveMaxResults int    `json:"provider_max_results"`
	DNSURL            string `json:"dns_url"`
	DNSToken          string `json:"dns_token"`
	DNSMaxResults     int    `json:"dns_max_results"`
}

func (ProviderConfiguration) String() string { return "[protected provider configuration]" }

// ConfigurationManager persists immutable encrypted versions. Job records store only the version ID.
type ConfigurationManager struct {
	tools    *toolrunner.Registry
	dns      networkenrich.Resolver
	dir      string
	aead     cipher.AEAD
	legacy   ProviderConfiguration
	fallback job.Executor
	sender   capability.BatchSender
	mu       sync.Mutex
}

func (m *ConfigurationManager) WithTools(tools *toolrunner.Registry) { m.tools = tools }

// WithDNSResolver sets the resolver runtime executors use for DNS work, so the
// configured upstreams apply to jobs built from ASM-managed configuration too.
func (m *ConfigurationManager) WithDNSResolver(resolver networkenrich.Resolver) { m.dns = resolver }

func NewConfigurationManager(dir string, legacy ProviderConfiguration, fallback job.Executor, sender capability.BatchSender) (*ConfigurationManager, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errRuntimeConfiguration
	}
	keyPath := filepath.Join(dir, "key")
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, key); err != nil {
			return nil, errRuntimeConfiguration
		}
		if err = writeConfigurationFile(dir, keyPath, key); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, errRuntimeConfiguration
		}
		key, err = os.ReadFile(keyPath)
	}
	info, statErr := os.Lstat(keyPath)
	if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || len(key) != 32 {
		return nil, errRuntimeConfiguration
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errRuntimeConfiguration
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errRuntimeConfiguration
	}
	manager := &ConfigurationManager{dir: dir, aead: aead, legacy: legacy, fallback: fallback, sender: sender}
	if _, err := os.Stat(manager.filename(0)); errors.Is(err, os.ErrNotExist) {
		raw, marshalErr := json.Marshal(legacy)
		if marshalErr != nil {
			return nil, errRuntimeConfiguration
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, errRuntimeConfiguration
		}
		sealed := aead.Seal(nonce, nonce, raw, []byte("0"))
		if err = writeConfigurationFile(dir, manager.filename(0), sealed); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, errRuntimeConfiguration
		}
	}
	baseline, err := manager.Load(0)
	if err != nil {
		return nil, err
	}
	manager.legacy = baseline
	return manager, nil
}
func writeConfigurationFile(dir, dest string, data []byte) error {
	f, err := os.CreateTemp(dir, ".configuration-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name) //nolint:errcheck
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Link(name, dest)
}
func (m *ConfigurationManager) filename(version uint64) string {
	return filepath.Join(m.dir, "v-"+strconv.FormatUint(version, 10)+".enc")
}
func (m *ConfigurationManager) Load(version uint64) (ProviderConfiguration, error) {
	var c ProviderConfiguration
	payload, err := os.ReadFile(m.filename(version))
	n := m.aead.NonceSize()
	if err != nil || len(payload) < n || len(payload) > 64<<10 {
		return c, errRuntimeConfiguration
	}
	raw, err := m.aead.Open(nil, payload[:n], payload[n:], []byte(strconv.FormatUint(version, 10)))
	if err != nil || json.Unmarshal(raw, &c) != nil {
		return c, errRuntimeConfiguration
	}
	return c, nil
}
func (m *ConfigurationManager) Save(version uint64, c ProviderConfiguration) error {
	if version == 0 {
		return errRuntimeConfiguration
	}
	if _, err := m.executor(c); err != nil {
		return errRuntimeConfiguration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, err := json.Marshal(c)
	if err != nil {
		return errRuntimeConfiguration
	}
	if existing, err := m.Load(version); err == nil {
		old, _ := json.Marshal(existing)
		if string(old) == string(raw) {
			return nil
		}
		return errRuntimeConfiguration
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return errRuntimeConfiguration
	}
	sealed := m.aead.Seal(nonce, nonce, raw, []byte(strconv.FormatUint(version, 10)))
	if err = writeConfigurationFile(m.dir, m.filename(version), sealed); err != nil {
		return errRuntimeConfiguration
	}
	return nil
}
func (m *ConfigurationManager) Current() (ProviderConfiguration, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return ProviderConfiguration{}, errRuntimeConfiguration
	}
	var latest uint64
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "v-") && strings.HasSuffix(entry.Name(), ".enc") {
			v, e := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "v-"), ".enc"), 10, 64)
			if e == nil && v > latest {
				latest = v
			}
		}
	}
	c, err := m.Load(latest)
	if latest == 0 {
		if c.FOFAMaxResults < 1 || c.FOFAMaxResults > 1000 {
			c.FOFAMaxResults = 1000
		}
		if c.PassiveMaxResults < 1 || c.PassiveMaxResults > 1000 {
			c.PassiveMaxResults = 500
		}
		if c.DNSMaxResults < 1 || c.DNSMaxResults > 500 {
			c.DNSMaxResults = 500
		}
	}
	return c, err
}
func (m *ConfigurationManager) Execute(ctx context.Context, request contract.ScanRequest) (job.ExecutionResult, error) {
	if request.JobType == "org_intel" {
		return m.fallback.Execute(ctx, request)
	}
	c, err := m.Load(request.ConfigurationVersion)
	if err != nil {
		return job.ExecutionResult{}, errRuntimeConfiguration
	}
	executor, err := m.buildExecutor(c, request.ConfigurationVersion == 0)
	if err != nil {
		return job.ExecutionResult{}, errRuntimeConfiguration
	}
	return executor.Execute(ctx, request)
}
func (m *ConfigurationManager) executor(c ProviderConfiguration) (job.Executor, error) {
	return m.buildExecutor(c, false)
}
func (m *ConfigurationManager) buildExecutor(c ProviderConfiguration, legacy bool) (job.Executor, error) {
	for _, n := range []int{c.FOFAMaxResults, c.PassiveMaxResults, c.DNSMaxResults} {
		if !legacy && (n < 1 || n > 1000) {
			return nil, errRuntimeConfiguration
		}
	}
	for _, value := range []string{c.FOFAEmail, c.FOFAKey, c.QuakeKey, c.HunterKey, c.PassiveToken, c.DNSToken} {
		if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, errRuntimeConfiguration
		}
	}
	if !legacy && c.DNSMaxResults > 500 {
		return nil, errRuntimeConfiguration
	}
	providers := []capability.PassiveProvider{}
	if !c.SubfinderDisabled && m.tools != nil && m.tools.Has("subfinder") {
		providers = append(providers, capability.NewSubfinderProvider(m.tools))
	}
	client := providerHTTPClient
	if legacy {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if c.QuakeEnabled {
		if c.QuakeKey == "" {
			return nil, errRuntimeConfiguration
		}
		providers = append(providers, capability.NewSpaceProvider("quake", c.QuakeKey, client, 1000))
	}
	if c.HunterEnabled {
		if c.HunterKey == "" {
			return nil, errRuntimeConfiguration
		}
		providers = append(providers, capability.NewSpaceProvider("hunter", c.HunterKey, client, 1000))
	}
	if c.FOFAEnabled {
		provider, err := capability.NewFOFAPassiveProvider(c.FOFAEmail, c.FOFAKey, "", client, c.FOFAMaxResults)
		if err != nil {
			return nil, errRuntimeConfiguration
		}
		providers = append(providers, provider)
	}
	if c.PassiveURL != "" {
		if !legacy && !validProviderURL(c.PassiveURL) {
			return nil, errRuntimeConfiguration
		}
		provider, err := capability.NewHTTPPassiveProvider(c.PassiveName, c.PassiveURL, c.PassiveToken, client, c.PassiveMaxResults)
		if err != nil {
			return nil, errRuntimeConfiguration
		}
		providers = append(providers, provider)
	}
	var resolver capability.Resolver = capability.NewNetResolver(m.dns, capability.DNSLookupTimeout)
	if c.DNSURL != "" {
		if !legacy && !validProviderURL(c.DNSURL) {
			return nil, errRuntimeConfiguration
		}
		var err error
		resolver, err = capability.NewHTTPResolver(c.DNSURL, c.DNSToken, client, c.DNSMaxResults)
		if err != nil {
			return nil, errRuntimeConfiguration
		}
	}
	return capability.NewPassiveExecutor(providers, resolver, m.sender), nil
}
func validProviderURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || len(value) > 2048 || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.EqualFold(u.Hostname(), "localhost") {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err != nil || !blockedProviderIP(ip)
}
func blockedProviderIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip == netip.MustParseAddr("fd00:ec2::254") {
		return true
	}
	if !ip.IsValid() || ip.IsLoopback() || !ip.IsGlobalUnicast() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "100::/64"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return true
		}
	}
	return false
}

var providerHTTPClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errRuntimeConfiguration
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 || len(ips) > 32 {
			return nil, errRuntimeConfiguration
		}
		for _, ip := range ips {
			if blockedProviderIP(ip) {
				return nil, errRuntimeConfiguration
			}
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}()

func (h *Handler) WithConfigurations(m *ConfigurationManager) *Handler {
	h.configurations = m
	return h
}

// This authenticated service-to-service endpoint is consumed by ASM, which returns only masks to browsers.
func (h *Handler) configuration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.authorized(r) {
		writeError(w, http.StatusUnauthorized, "INVALID_AUTH", "invalid engine authentication")
		return
	}
	if h.configurations == nil {
		writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "configuration unavailable")
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/management/configuration" {
		c, err := h.configurations.Current()
		if err != nil {
			writeError(w, 503, "UNAVAILABLE", "configuration unavailable")
			return
		}
		writeJSON(w, 200, c)
		return
	}
	if r.Method != http.MethodPut {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/management/configurations/"), 10, 64)
	if err != nil || v == 0 {
		writeError(w, 422, "INVALID_VERSION", "invalid configuration version")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var c ProviderConfiguration
	if err = decoder.Decode(&c); err != nil {
		writeError(w, 422, "INVALID_CONFIGURATION", "invalid configuration")
		return
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, 422, "INVALID_CONFIGURATION", "invalid configuration")
		return
	}
	if err = h.configurations.Save(v, c); err != nil {
		writeError(w, 409, "CONFIGURATION_CONFLICT", "configuration invalid or version already exists")
		return
	}
	writeJSON(w, 200, map[string]any{"version": v})
}
