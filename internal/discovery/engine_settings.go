package discovery

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/netguard"
)

// Configuration errors deliberately exclude URLs, payloads, and secret values.
var (
	ErrEngineSettingsInvalid       = errors.New("引擎配置无效，请检查字段")
	ErrEngineSettingsConflict      = errors.New("配置已被其他管理员修改，请重新加载")
	ErrEngineSettingsUnavailable   = errors.New("配置存储或加密密钥不可用")
	ErrProviderSettingsUnavailable = errors.New("无法读取引擎现有数据源配置，请检查连接并确认 Baiyan 已升级")
)

// ProviderSettings is transported only between authenticated services, never to the browser.
type ProviderSettings struct {
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

// EngineSettings is encrypted at rest. Use SettingsView for every user-facing response.
type EngineSettings struct {
	PassiveURL       string               `json:"passive_url"`
	PassiveToken     string               `json:"passive_token"`
	ActiveURL        string               `json:"active_url"`
	ActiveAccessKey  string               `json:"active_access_key"`
	ActiveSecretKey  string               `json:"active_secret_key"`
	ActiveProjectMap string               `json:"active_project_map"`
	Policy           ActiveDispatchPolicy `json:"policy"`
	Providers        *ProviderSettings    `json:"providers,omitempty"`
}

func (EngineSettings) String() string   { return "[encrypted engine configuration]" }
func (ProviderSettings) String() string { return "[protected provider configuration]" }

// SettingsFromEnvironment captures the one-time migration baseline.
func SettingsFromEnvironment(c EngineRouterConfig, p ActiveDispatchPolicy) EngineSettings {
	return EngineSettings{PassiveURL: c.PassiveBaseURL, PassiveToken: c.PassiveToken, ActiveURL: c.ActiveBaseURL, ActiveAccessKey: c.ActiveAccessKey, ActiveSecretKey: c.ActiveSecretKey, ActiveProjectMap: c.ActiveProjectMap, Policy: p}
}

// RouterConfig returns the connection parameters used to build immutable adapters.
func (c EngineSettings) RouterConfig() EngineRouterConfig {
	return EngineRouterConfig{PassiveBaseURL: c.PassiveURL, PassiveToken: c.PassiveToken, ActiveBaseURL: c.ActiveURL, ActiveAccessKey: c.ActiveAccessKey, ActiveSecretKey: c.ActiveSecretKey, ActiveProjectMap: c.ActiveProjectMap}
}

// EngineSettingsSnapshot An immutable revision used by new or previously bound tasks.
type EngineSettingsSnapshot struct {
	Version  uint64
	Settings EngineSettings
}

// Router builds adapters bound to this configuration version.
func (s EngineSettingsSnapshot) Router() (*TaskTypeEngineRouter, EngineRouterConfigStatus) {
	client := managedEngineClient()
	router, status := NewConfiguredEngineRouter(s.Settings.RouterConfig(), client, client)
	if a, ok := router.passive.(*HTTPEngineAdapter); ok && s.Settings.Providers != nil {
		a.configurationVersion = s.Version
		a.providerSettings = s.Settings.Providers
	}
	return router, status
}

// EngineSettingsStore Encrypted configuration history and transactional audit persistence.
type EngineSettingsStore struct {
	db   *sql.DB
	aead cipher.AEAD
}

// NewEngineSettingsStore binds a database to a 256-bit configuration encryption key.
func NewEngineSettingsStore(db *sql.DB, key []byte) (*EngineSettingsStore, error) {
	if db == nil || len(key) != 32 {
		return nil, ErrEngineSettingsUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEngineSettingsUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEngineSettingsUnavailable
	}
	return &EngineSettingsStore{db: db, aead: aead}, nil
}

// LoadEngineSettingsKey reads a deployment-owned, owner-only raw key file.
func LoadEngineSettingsKey(path string) ([]byte, error) {
	info, err := os.Stat(path) // #nosec G703 -- path comes only from trusted deployment configuration, never HTTP input.
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrEngineSettingsUnavailable
	}
	key, err := os.ReadFile(path) // #nosec G304 G703 -- owner-only deployment key file; no user-supplied path.
	if err != nil || len(key) != 32 {
		return nil, ErrEngineSettingsUnavailable
	}
	return key, nil
}
func (s *EngineSettingsStore) seal(version uint64, c EngineSettings) ([]byte, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, ErrEngineSettingsInvalid
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrEngineSettingsUnavailable
	}
	return s.aead.Seal(nonce, nonce, raw, []byte(fmt.Sprintf("asm-engine-settings:%d", version))), nil
}
func (s *EngineSettingsStore) open(version uint64, payload []byte) (EngineSettings, error) {
	var out EngineSettings
	n := s.aead.NonceSize()
	if len(payload) < n {
		return out, ErrEngineSettingsUnavailable
	}
	raw, err := s.aead.Open(nil, payload[:n], payload[n:], []byte(fmt.Sprintf("asm-engine-settings:%d", version)))
	if err != nil || json.Unmarshal(raw, &out) != nil {
		return out, ErrEngineSettingsUnavailable
	}
	return out, nil
}

// Bootstrap imports process settings once and verifies the encryption key on later starts.
func (s *EngineSettingsStore) Bootstrap(ctx context.Context, c EngineSettings) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrEngineSettingsUnavailable
	}
	defer tx.Rollback() //nolint:errcheck
	q := dbgen.New(tx)
	v, err := q.LockEngineSettingsHead(ctx)
	if err != nil {
		return ErrEngineSettingsUnavailable
	}
	if v > 0 {
		row, err := q.GetEngineSettingsVersion(ctx, v)
		if err != nil {
			return ErrEngineSettingsUnavailable
		}
		if _, err = s.open(v, row.EncryptedPayload); err != nil {
			return err
		}
		return tx.Commit()
	}
	encrypted, err := s.seal(1, c)
	if err != nil {
		return err
	}
	if err = q.CreateEngineSettingsVersion(ctx, dbgen.CreateEngineSettingsVersionParams{Version: 1, EncryptedPayload: encrypted, CreatedBy: "system"}); err != nil {
		return ErrEngineSettingsUnavailable
	}
	if err = q.SetEngineSettingsHead(ctx, 1); err != nil {
		return ErrEngineSettingsUnavailable
	}
	if err = audit.NewService(audit.NewRepository(q)).Record(ctx, audit.Event{TenantID: "platform", OrgID: "platform", ActorID: "system", ActorType: audit.ActorSystem, Action: "platform.discovery_engine.configuration.bootstrap", ResourceType: ResourceTypeEngine, ResourceID: "configuration", After: map[string]any{"version": 1}}); err != nil {
		return ErrEngineSettingsUnavailable
	}
	return tx.Commit()
}

// Latest loads the current version without falling back to stale process settings.
func (s *EngineSettingsStore) Latest(ctx context.Context) (EngineSettingsSnapshot, error) {
	v, err := dbgen.New(s.db).GetEngineSettingsHead(ctx)
	if err != nil {
		return EngineSettingsSnapshot{}, ErrEngineSettingsUnavailable
	}
	return s.Version(ctx, v)
}

// Version decrypts and authenticates an immutable stored revision.
func (s *EngineSettingsStore) Version(ctx context.Context, v uint64) (EngineSettingsSnapshot, error) {
	row, err := dbgen.New(s.db).GetEngineSettingsVersion(ctx, v)
	if err != nil {
		return EngineSettingsSnapshot{}, ErrEngineSettingsUnavailable
	}
	c, err := s.open(v, row.EncryptedPayload)
	return EngineSettingsSnapshot{Version: v, Settings: c}, err
}

// ForRun loads a project-scoped run binding; historical runs use the preserved baseline.
func (s *EngineSettingsStore) ForRun(ctx context.Context, projectID, runID uint64) (EngineSettingsSnapshot, error) {
	v, err := dbgen.New(s.db).GetEngineRunSettings(ctx, dbgen.GetEngineRunSettingsParams{ProjectID: projectID, RunID: runID})
	if errors.Is(err, sql.ErrNoRows) {
		v = 1
	} else if err != nil {
		return EngineSettingsSnapshot{}, ErrEngineSettingsUnavailable
	}
	return s.Version(ctx, v)
}

// Save atomically appends an immutable version, updates its pointer, and writes the audit event.
func (s *EngineSettingsStore) Save(ctx context.Context, expected uint64, c EngineSettings, event audit.Event) (EngineSettingsSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EngineSettingsSnapshot{}, ErrEngineSettingsUnavailable
	}
	defer tx.Rollback() //nolint:errcheck
	q := dbgen.New(tx)
	v, err := q.LockEngineSettingsHead(ctx)
	if err != nil {
		return EngineSettingsSnapshot{}, ErrEngineSettingsUnavailable
	}
	if v != expected {
		return EngineSettingsSnapshot{}, ErrEngineSettingsConflict
	}
	next := v + 1
	encrypted, err := s.seal(next, c)
	if err != nil {
		return EngineSettingsSnapshot{}, err
	}
	if err = q.CreateEngineSettingsVersion(ctx, dbgen.CreateEngineSettingsVersionParams{Version: next, EncryptedPayload: encrypted, CreatedBy: event.ActorID}); err != nil {
		return EngineSettingsSnapshot{}, ErrEngineSettingsUnavailable
	}
	if err = q.SetEngineSettingsHead(ctx, next); err != nil {
		return EngineSettingsSnapshot{}, ErrEngineSettingsUnavailable
	}
	event.Before = map[string]any{"version": v}
	event.After = map[string]any{"version": next}
	if err = audit.NewService(audit.NewRepository(q)).Record(ctx, event); err != nil {
		return EngineSettingsSnapshot{}, ErrEngineSettingsUnavailable
	}
	if err = tx.Commit(); err != nil {
		return EngineSettingsSnapshot{}, ErrEngineSettingsUnavailable
	}
	return EngineSettingsSnapshot{Version: next, Settings: c}, nil
}

func validateManagedURL(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 2048 {
		return ErrEngineSettingsInvalid
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrEngineSettingsInvalid
	}
	if strings.EqualFold(u.Hostname(), "localhost") {
		return ErrEngineSettingsInvalid
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && blockedEngineAddress(ip) {
		return ErrEngineSettingsInvalid
	}
	return nil
}
func blockedEngineAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip == netip.MustParseAddr("fd00:ec2::254") {
		return true
	}
	return netguard.IsDangerousAddr(ip) && !ip.IsPrivate()
}

// Engines may be on explicitly configured private networks; metadata/link-local and redirects are always refused.
var sharedManagedEngineClient = buildManagedEngineClient()

func managedEngineClient() *http.Client { return sharedManagedEngineClient }
func buildManagedEngineClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, ErrEngineSettingsInvalid
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 || len(addresses) > 32 {
			return nil, ErrEngineSettingsUnavailable
		}
		for _, ip := range addresses {
			if blockedEngineAddress(ip) {
				return nil, ErrEngineSettingsInvalid
			}
		}
		var dialer net.Dialer
		dialer.Timeout = 5 * time.Second
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
	}
	return &http.Client{Timeout: 12 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var secretSettingKeys = map[string]bool{"passive_token": true, "active_access_key": true, "active_secret_key": true, "fofa_email": true, "fofa_key": true, "quake_key": true, "hunter_key": true, "provider_token": true, "dns_token": true}

func settingsValues(c EngineSettings) map[string]string {
	v := map[string]string{"passive_url": c.PassiveURL, "passive_token": c.PassiveToken, "active_url": c.ActiveURL, "active_access_key": c.ActiveAccessKey, "active_secret_key": c.ActiveSecretKey, "active_project_map": c.ActiveProjectMap, "active_enabled": strconv.FormatBool(c.Policy.Enabled), "require_approval": strconv.FormatBool(c.Policy.RequireApproval), "require_ownership": strconv.FormatBool(c.Policy.RequireOwnership)}
	if p := c.Providers; p != nil {
		v["subfinder_disabled"] = strconv.FormatBool(p.SubfinderDisabled)
		v["quake_enabled"] = strconv.FormatBool(p.QuakeEnabled)
		v["quake_key"] = p.QuakeKey
		v["hunter_enabled"] = strconv.FormatBool(p.HunterEnabled)
		v["hunter_key"] = p.HunterKey
		v["fofa_enabled"] = strconv.FormatBool(p.FOFAEnabled)
		v["fofa_email"] = p.FOFAEmail
		v["fofa_key"] = p.FOFAKey
		v["fofa_max_results"] = strconv.Itoa(p.FOFAMaxResults)
		v["provider_name"] = p.PassiveName
		v["provider_url"] = p.PassiveURL
		v["provider_token"] = p.PassiveToken
		v["provider_max_results"] = strconv.Itoa(p.PassiveMaxResults)
		v["dns_url"] = p.DNSURL
		v["dns_token"] = p.DNSToken
		v["dns_max_results"] = strconv.Itoa(p.DNSMaxResults)
	}
	return v
}

// EngineSettingsView Browser-safe configuration metadata; secrets are represented only by masks.
type EngineSettingsView struct {
	Version          uint64                             `json:"version"`
	Values           map[string]string                  `json:"values"`
	Secrets          map[string]EngineCredentialSummary `json:"secrets"`
	ProvidersManaged bool                               `json:"providers_managed"`
	ProviderError    string                             `json:"provider_error,omitempty"`
}

func settingsView(snapshot EngineSettingsSnapshot) EngineSettingsView {
	v := settingsValues(snapshot.Settings)
	secrets := map[string]EngineCredentialSummary{}
	for key := range secretSettingKeys {
		secrets[key] = credentialSummary(key, key, v[key], false)
		delete(v, key)
	}
	return EngineSettingsView{Version: snapshot.Version, Values: v, Secrets: secrets, ProvidersManaged: snapshot.Settings.Providers != nil}
}

// UpdateEngineSettingsInput Version-checked write-only configuration changes.
type UpdateEngineSettingsInput struct {
	Version      uint64            `json:"version"`
	Values       map[string]string `json:"values"`
	ClearSecrets []string          `json:"clear_secrets"`
	Reason       string            `json:"reason"`
}

func applySettingsPatch(c EngineSettings, in UpdateEngineSettingsInput) (EngineSettings, error) {
	values := settingsValues(c)
	for k, v := range in.Values {
		if _, ok := values[k]; !ok {
			return c, ErrEngineSettingsInvalid
		}
		if (secretSettingKeys[k] && len(v) > 4096) || len(v) > maxActiveProjectMapBytes || strings.ContainsAny(v, "\x00\r\n") && k != "active_project_map" {
			return c, ErrEngineSettingsInvalid
		}
		if secretSettingKeys[k] && v == "" {
			continue
		}
		values[k] = strings.TrimSpace(v)
	}
	for _, k := range in.ClearSecrets {
		if !secretSettingKeys[k] {
			return c, ErrEngineSettingsInvalid
		}
		values[k] = ""
	}
	c.PassiveURL = values["passive_url"]
	c.PassiveToken = values["passive_token"]
	c.ActiveURL = values["active_url"]
	c.ActiveAccessKey = values["active_access_key"]
	c.ActiveSecretKey = values["active_secret_key"]
	c.ActiveProjectMap = values["active_project_map"]
	var err error
	c.Policy.Enabled, err = strconv.ParseBool(values["active_enabled"])
	if err != nil {
		return c, ErrEngineSettingsInvalid
	}
	c.Policy.RequireApproval, err = strconv.ParseBool(values["require_approval"])
	if err != nil {
		return c, ErrEngineSettingsInvalid
	}
	c.Policy.RequireOwnership, err = strconv.ParseBool(values["require_ownership"])
	if err != nil {
		return c, ErrEngineSettingsInvalid
	}
	if c.Providers != nil {
		p := *c.Providers
		c.Providers = &p
		p.SubfinderDisabled, err = strconv.ParseBool(values["subfinder_disabled"])
		if err != nil {
			return c, ErrEngineSettingsInvalid
		}
		p.QuakeEnabled, err = strconv.ParseBool(values["quake_enabled"])
		if err != nil {
			return c, ErrEngineSettingsInvalid
		}
		p.HunterEnabled, err = strconv.ParseBool(values["hunter_enabled"])
		if err != nil {
			return c, ErrEngineSettingsInvalid
		}
		p.QuakeKey = values["quake_key"]
		p.HunterKey = values["hunter_key"]
		if p.QuakeEnabled && p.QuakeKey == "" || p.HunterEnabled && p.HunterKey == "" {
			return c, ErrEngineSettingsInvalid
		}
		p.FOFAEnabled, err = strconv.ParseBool(values["fofa_enabled"])
		if err != nil {
			return c, ErrEngineSettingsInvalid
		}
		p.FOFAEmail = values["fofa_email"]
		p.FOFAKey = values["fofa_key"]
		p.PassiveName = values["provider_name"]
		p.PassiveURL = values["provider_url"]
		p.PassiveToken = values["provider_token"]
		p.DNSURL = values["dns_url"]
		p.DNSToken = values["dns_token"]
		p.FOFAMaxResults, err = strconv.Atoi(values["fofa_max_results"])
		if err != nil {
			return c, ErrEngineSettingsInvalid
		}
		p.PassiveMaxResults, err = strconv.Atoi(values["provider_max_results"])
		if err != nil {
			return c, ErrEngineSettingsInvalid
		}
		p.DNSMaxResults, err = strconv.Atoi(values["dns_max_results"])
		if err != nil {
			return c, ErrEngineSettingsInvalid
		}
		for _, limit := range []int{p.FOFAMaxResults, p.PassiveMaxResults, p.DNSMaxResults} {
			if limit < 1 || limit > 1000 {
				return c, ErrEngineSettingsInvalid
			}
		}
		if p.DNSMaxResults > 500 {
			return c, ErrEngineSettingsInvalid
		}
		if p.FOFAEnabled && (p.FOFAEmail == "" || p.FOFAKey == "") {
			return c, ErrEngineSettingsInvalid
		}
		if p.PassiveURL != "" && (p.PassiveName == "" || len(p.PassiveName) > 64) {
			return c, ErrEngineSettingsInvalid
		}
		if validateManagedURL(p.PassiveURL) != nil || validateManagedURL(p.DNSURL) != nil {
			return c, ErrEngineSettingsInvalid
		}
	}
	if validateManagedURL(c.PassiveURL) != nil || validateManagedURL(c.ActiveURL) != nil {
		return c, ErrEngineSettingsInvalid
	}
	_, status := NewConfiguredEngineRouter(c.RouterConfig(), managedEngineClient(), managedEngineClient())
	if status.Passive.Configured && !status.Passive.Ready || status.Active.Configured && !status.Active.Ready || c.Policy.Enabled && !status.Active.Ready {
		return c, ErrEngineSettingsInvalid
	}
	return c, nil
}
