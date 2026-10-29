//revive:disable:exported

package discovery

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

const (
	EngineHealthHealthy      = "healthy"
	EngineHealthDegraded     = "degraded"
	EngineHealthUnreachable  = "unreachable"
	EngineHealthUnconfigured = "unconfigured"
	EngineHealthUnknown      = "unknown"

	WorkerEngineStatusOnline  = "online"
	WorkerEngineStatusStale   = "stale"
	WorkerEngineStatusUnknown = "unknown"

	ActionEngineConnectionCheck = "platform.discovery_engine.check"
	ResourceTypeEngine          = "discovery_engine"

	defaultEngineManagementTimeout = 5 * time.Second
	defaultWorkerStatusTimeout     = time.Second
	maskedSecretPrefix             = "••••••••" // #nosec G101 -- fixed masking placeholder, not a credential.
)

var (
	ErrEngineManagementForbidden    = errors.New("discovery: engine management permission denied")
	ErrEngineManagementInvalidRoute = errors.New("discovery: invalid managed engine route")
	ErrEngineManagementUnavailable  = errors.New("discovery: engine management unavailable")
)

type EngineCredentialSummary struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Configured  bool   `json:"configured"`
	MaskedValue string `json:"masked_value"`
}

type EngineProviderSummary struct {
	Key         string                    `json:"key"`
	Name        string                    `json:"name"`
	Configured  bool                      `json:"configured"`
	Credentials []EngineCredentialSummary `json:"credentials"`
}

type EngineNodeSummary struct {
	NodeID       string   `json:"node_id"`
	Capabilities []string `json:"capabilities"`
}

type ManagedEngineSummary struct {
	ConfigurationVersion uint64                    `json:"configuration_version"`
	Route                EngineRoute               `json:"route"`
	Key                  string                    `json:"key"`
	Name                 string                    `json:"name"`
	InstanceID           string                    `json:"instance_id,omitempty"`
	Configured           bool                      `json:"configured"`
	Ready                bool                      `json:"ready"`
	Health               string                    `json:"health"`
	BaseURL              string                    `json:"base_url"`
	Capabilities         []string                  `json:"capabilities"`
	Credentials          []EngineCredentialSummary `json:"credentials"`
	Providers            []EngineProviderSummary   `json:"providers,omitempty"`
	Nodes                []EngineNodeSummary       `json:"nodes,omitempty"`
	LastCheckedAt        string                    `json:"last_checked_at,omitempty"`
	LatencyMS            int64                     `json:"latency_ms,omitempty"`
	ErrorSummary         string                    `json:"error_summary,omitempty"`
	ProjectMapSize       int                       `json:"project_mapping_count,omitempty"`
}

type EngineWorkerSummary struct {
	Status        string `json:"status"`
	LastSeenAt    string `json:"last_seen_at,omitempty"`
	ConfigMatches *bool  `json:"config_matches,omitempty"`
}

type EngineManagementOverview struct {
	ConfigurationVersion uint64                 `json:"configuration_version"`
	Editable             bool                   `json:"editable"`
	Items                []ManagedEngineSummary `json:"items"`
	ActivePolicy         ActiveDispatchPolicy   `json:"active_policy"`
	Worker               EngineWorkerSummary    `json:"worker"`
}

type engineManagementUserResolver interface {
	GetByID(context.Context, uint64) (*auth.User, error)
	GetGlobalRole(context.Context, uint64) (string, error)
}

type engineManagementAuditRecorder interface {
	Record(context.Context, audit.Event) error
}

type passiveEngineInspector interface {
	CheckManagementStatus(context.Context) (PassiveEngineManagementStatus, error)
}

type activeEngineInspector interface {
	CheckReadiness(context.Context) (ActiveEngineReadiness, error)
}

type engineWorkerStatusReader interface {
	ReadWorkerEngineStatus(context.Context) (WorkerEngineRuntimeStatus, error)
}

type EngineManagementService struct {
	settings     *EngineSettingsStore
	version      uint64
	checks       *engineCheckCache
	config       EngineRouterConfig
	configStatus EngineRouterConfigStatus
	policy       ActiveDispatchPolicy
	users        engineManagementUserResolver
	audit        engineManagementAuditRecorder
	passive      passiveEngineInspector
	active       activeEngineInspector
	worker       engineWorkerStatusReader
	now          func() time.Time
	timeout      time.Duration
}

func NewEngineManagementService(
	config EngineRouterConfig,
	configStatus EngineRouterConfigStatus,
	router *TaskTypeEngineRouter,
	policy ActiveDispatchPolicy,
	users engineManagementUserResolver,
	auditSink engineManagementAuditRecorder,
	worker engineWorkerStatusReader,
) *EngineManagementService {
	service := &EngineManagementService{
		config: config, configStatus: configStatus, policy: policy, checks: &engineCheckCache{items: make(map[string]ManagedEngineSummary)},
		users: users, audit: auditSink, worker: worker,
		now: time.Now, timeout: defaultEngineManagementTimeout,
	}
	if router != nil {
		if adapter, err := router.EngineForTaskType(TaskTypePassiveIntel); err == nil {
			service.passive, _ = adapter.(passiveEngineInspector)
		}
		if adapter, err := router.EngineForTaskType(TaskTypePortProbe); err == nil {
			service.active, _ = adapter.(activeEngineInspector)
		}
	}
	return service
}

// List reads local configuration and prior results; it never waits for engine probes.
func (s *EngineManagementService) List(ctx context.Context, actorID string) (EngineManagementOverview, error) {
	if _, err := s.authorize(ctx, actorID); err != nil {
		return EngineManagementOverview{}, err
	}
	current, err := s.resolvedSettings(ctx)
	if err != nil {
		return EngineManagementOverview{}, err
	}
	items := []ManagedEngineSummary{current.passiveBaseSummary(), current.activeBaseSummary()}
	for i := range items {
		items[i].ConfigurationVersion = current.version
		if prior, ok := s.checks.get(current.version, items[i].Route); ok {
			items[i] = prior
		}
	}
	return EngineManagementOverview{Items: items, ActivePolicy: current.policy, Worker: current.workerSummary(ctx), ConfigurationVersion: current.version, Editable: s.settings != nil}, nil
}

// Check re-runs one read-only connection test and writes a platform-level audit
// record that deliberately excludes URLs and credential summaries.
func (s *EngineManagementService) Check(
	ctx context.Context,
	actorID string,
	route EngineRoute,
	meta AuditMeta,
) (ManagedEngineSummary, error) {
	actor, err := s.authorize(ctx, actorID)
	if err != nil {
		return ManagedEngineSummary{}, err
	}
	if route != EngineRoutePassive && route != EngineRouteActive {
		return ManagedEngineSummary{}, ErrEngineManagementInvalidRoute
	}
	if s.audit == nil {
		return ManagedEngineSummary{}, ErrEngineManagementUnavailable
	}

	current, err := s.resolvedSettings(ctx)
	if err != nil {
		return ManagedEngineSummary{}, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, current.timeout)
	defer cancel()
	summary := current.inspect(checkCtx, route)
	summary.ConfigurationVersion = current.version
	result := audit.ResultSuccess
	errorCode := ""
	if summary.Health != EngineHealthHealthy {
		result = audit.ResultFailure
		errorCode = "ENGINE_NOT_READY"
	}
	if err := s.audit.Record(ctx, audit.Event{
		TenantID: actor.TenantID, OrgID: actor.OrgID, ActorID: actorID,
		ActorType: audit.ActorUser, Action: ActionEngineConnectionCheck,
		ResourceType: ResourceTypeEngine, ResourceID: string(route), Result: result,
		IP: meta.IP, UserAgent: meta.UserAgent, RequestID: meta.RequestID,
		After: map[string]any{
			"route": route, "health": summary.Health, "ready": summary.Ready,
			"latency_ms": summary.LatencyMS,
		},
		ErrorCode: errorCode,
	}); err != nil {
		return ManagedEngineSummary{}, ErrEngineManagementUnavailable
	}
	s.checks.put(current.version, summary)
	return summary, nil
}

func (s *EngineManagementService) inspect(ctx context.Context, route EngineRoute) ManagedEngineSummary {
	switch route {
	case EngineRoutePassive:
		return s.inspectPassive(ctx)
	case EngineRouteActive:
		return s.inspectActive(ctx)
	default:
		return ManagedEngineSummary{Route: route, Health: EngineHealthUnknown}
	}
}

func (s *EngineManagementService) passiveBaseSummary() ManagedEngineSummary {
	summary := ManagedEngineSummary{
		Route: EngineRoutePassive, Key: "baiyan", Name: "Baiyan 被动引擎",
		Configured: s.configStatus.Passive.Configured,
		BaseURL:    safeManagedBaseURL(s.config.PassiveBaseURL),
		Health:     EngineHealthUnknown,
		Capabilities: []string{
			TaskTypePassiveIntel, TaskTypeDNS, TaskTypeOrgIntel,
		},
		Credentials: []EngineCredentialSummary{
			credentialSummary("engine_token", "Engine Token", s.config.PassiveToken, false),
		},
	}
	if !summary.Configured {
		summary.Health = EngineHealthUnconfigured
		return summary
	}
	if !s.configStatus.Passive.Ready || s.passive == nil {
		summary.Health = EngineHealthDegraded
		summary.ErrorSummary = "引擎配置不完整或无效"
		return summary
	}

	return summary
}

func (s *EngineManagementService) inspectPassive(ctx context.Context) ManagedEngineSummary {
	summary := s.passiveBaseSummary()
	if summary.Health != EngineHealthUnknown {
		return summary
	}
	if adapter, ok := s.passive.(*HTTPEngineAdapter); ok {
		if err := adapter.ensureProviderConfiguration(ctx); err != nil {
			summary.Health = EngineHealthUnreachable
			summary.ErrorSummary = "数据源配置无法同步到 Baiyan"
			return summary
		}
	}

	started := s.now().UTC()
	checkCtx, cancel := context.WithTimeout(ctx, s.timeout)
	status, err := s.passive.CheckManagementStatus(checkCtx)
	cancel()
	summary.LastCheckedAt = managementTimestamp(started)
	summary.LatencyMS = elapsedMilliseconds(started, s.now().UTC())
	if err != nil {
		summary.Health = EngineHealthUnreachable
		summary.ErrorSummary = "无法连接 Baiyan 或凭据校验失败"
		return summary
	}

	summary.InstanceID = safeManagementText(status.EngineID, 128)
	summary.Capabilities = safeCapabilities(status.Capabilities, summary.Capabilities)
	summary.Providers = safeProviderSummaries(status.Providers)
	summary.Ready = strings.EqualFold(strings.TrimSpace(status.Status), "ready")
	if summary.Ready {
		summary.Health = EngineHealthHealthy
	} else {
		summary.Health = EngineHealthDegraded
		summary.ErrorSummary = "Baiyan 未就绪"
	}
	return summary
}

func (s *EngineManagementService) activeBaseSummary() ManagedEngineSummary {
	projectMap, _ := parseActiveEngineProjectMap(s.config.ActiveProjectMap)
	summary := ManagedEngineSummary{
		Route: EngineRouteActive, Key: "active_aksk", Name: "主动扫描引擎",
		Configured:     s.configStatus.Active.Configured,
		BaseURL:        safeManagedBaseURL(s.config.ActiveBaseURL),
		Health:         EngineHealthUnknown,
		ProjectMapSize: len(projectMap),
		Capabilities:   []string{TaskTypePortProbe, TaskTypeWebProbe, TaskTypeFingerprint},
		Credentials: []EngineCredentialSummary{
			credentialSummary("access_key", "Active AK", s.config.ActiveAccessKey, true),
			credentialSummary("secret_key", "Active SK", s.config.ActiveSecretKey, false),
		},
	}
	if !summary.Configured {
		summary.Health = EngineHealthUnconfigured
		return summary
	}
	if !s.configStatus.Active.Ready || s.active == nil {
		summary.Health = EngineHealthDegraded
		summary.ErrorSummary = "引擎配置不完整或无效"
		return summary
	}

	return summary
}

func (s *EngineManagementService) inspectActive(ctx context.Context) ManagedEngineSummary {
	summary := s.activeBaseSummary()
	if summary.Health != EngineHealthUnknown {
		return summary
	}

	started := s.now().UTC()
	checkCtx, cancel := context.WithTimeout(ctx, s.timeout)
	readiness, err := s.active.CheckReadiness(checkCtx)
	cancel()
	summary.LastCheckedAt = managementTimestamp(started)
	summary.LatencyMS = elapsedMilliseconds(started, s.now().UTC())
	if err != nil {
		summary.Health = EngineHealthUnreachable
		summary.ErrorSummary = "无法连接主动引擎或 AK/SK 校验失败"
		return summary
	}

	summary.Nodes = make([]EngineNodeSummary, 0, len(readiness.OnlineNodes))
	seenNodes := make(map[string]struct{}, len(readiness.OnlineNodes))
	for _, node := range readiness.OnlineNodes {
		nodeID := safeManagementText(node.NodeID, 128)
		if nodeID == "" {
			continue
		}
		if _, duplicate := seenNodes[nodeID]; duplicate {
			continue
		}
		seenNodes[nodeID] = struct{}{}
		summary.Nodes = append(summary.Nodes, EngineNodeSummary{
			NodeID:       nodeID,
			Capabilities: safeCapabilities(node.Capabilities, nil),
		})
	}
	summary.Ready = len(summary.Nodes) > 0
	if summary.Ready {
		summary.Health = EngineHealthHealthy
	} else {
		summary.Health = EngineHealthDegraded
		summary.ErrorSummary = "主动引擎 API 可用，但没有在线执行节点"
	}
	return summary
}

func (s *EngineManagementService) authorize(ctx context.Context, actorID string) (*auth.User, error) {
	if s == nil || s.users == nil {
		return nil, ErrEngineManagementUnavailable
	}
	id, err := strconv.ParseUint(strings.TrimSpace(actorID), 10, 64)
	if err != nil || id == 0 {
		return nil, ErrEngineManagementForbidden
	}
	actor, err := s.users.GetByID(ctx, id)
	if err != nil || actor == nil || !actor.IsActive() {
		return nil, ErrEngineManagementForbidden
	}
	role, err := s.users.GetGlobalRole(ctx, id)
	if err != nil {
		return nil, ErrEngineManagementUnavailable
	}
	if !asmcasbin.RoleHasPerm(role, asmcasbin.PermAdminManage) {
		return nil, ErrEngineManagementForbidden
	}
	return actor, nil
}

func (s *EngineManagementService) workerSummary(ctx context.Context) EngineWorkerSummary {
	unknown := EngineWorkerSummary{Status: WorkerEngineStatusUnknown}
	if s.worker == nil {
		return unknown
	}
	readCtx, cancel := context.WithTimeout(ctx, defaultWorkerStatusTimeout)
	status, err := s.worker.ReadWorkerEngineStatus(readCtx)
	cancel()
	if err != nil || status.UpdatedAt.IsZero() {
		return unknown
	}
	now := s.now().UTC()
	// A timestamp too far in the future usually means clock skew or a corrupt
	// heartbeat. Do not report that worker as online: a negative duration would
	// otherwise bypass the stale check.
	if status.UpdatedAt.After(now.Add(30 * time.Second)) {
		return unknown
	}
	out := EngineWorkerSummary{Status: WorkerEngineStatusOnline, LastSeenAt: managementTimestamp(status.UpdatedAt)}
	if now.Sub(status.UpdatedAt) > WorkerEngineHeartbeatTTL {
		out.Status = WorkerEngineStatusStale
	}
	matches := status.ConfigFingerprint == EngineRuntimeConfigFingerprint(s.config, s.policy) && status.ConfigurationVersion == s.version
	out.ConfigMatches = &matches
	return out
}

func credentialSummary(key, label, value string, identifier bool) EngineCredentialSummary {
	configured := strings.TrimSpace(value) != ""
	masked := ""
	if configured {
		if identifier {
			masked = MaskEngineIdentifier(value)
		} else {
			masked = MaskEngineSecret(value)
		}
	}
	return EngineCredentialSummary{Key: key, Label: label, Configured: configured, MaskedValue: masked}
}

func MaskEngineSecret(value string) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) == 0 {
		return ""
	}
	if len(runes) <= 8 {
		return maskedSecretPrefix
	}
	return maskedSecretPrefix + string(runes[len(runes)-4:])
}

func MaskEngineIdentifier(value string) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) == 0 {
		return ""
	}
	if len(runes) <= 8 {
		return maskedSecretPrefix
	}
	return string(runes[:4]) + "••••" + string(runes[len(runes)-4:])
}

func safeProviderSummaries(providers []PassiveEngineProviderStatus) []EngineProviderSummary {
	if len(providers) > 32 {
		providers = providers[:32]
	}
	out := make([]EngineProviderSummary, 0, len(providers))
	seenProviders := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		item := EngineProviderSummary{
			Key: safeManagementText(provider.Key, 64), Name: safeManagementText(provider.Name, 128),
			Configured: provider.Configured, Credentials: make([]EngineCredentialSummary, 0, len(provider.Credentials)),
		}
		if item.Key == "" {
			continue
		}
		if _, duplicate := seenProviders[item.Key]; duplicate {
			continue
		}
		seenProviders[item.Key] = struct{}{}
		credentials := provider.Credentials
		if len(credentials) > 16 {
			credentials = credentials[:16]
		}
		seenCredentials := make(map[string]struct{}, len(credentials))
		for _, credential := range credentials {
			credentialKey := safeManagementText(credential.Key, 64)
			if credentialKey == "" {
				continue
			}
			if _, duplicate := seenCredentials[credentialKey]; duplicate {
				continue
			}
			seenCredentials[credentialKey] = struct{}{}
			masked := safeMaskedValue(credential.MaskedValue)
			if !credential.Configured {
				masked = ""
			}
			item.Credentials = append(item.Credentials, EngineCredentialSummary{
				Key: credentialKey, Label: providerCredentialLabel(item.Key, credentialKey),
				Configured: credential.Configured, MaskedValue: masked,
			})
		}
		out = append(out, item)
	}
	return out
}

func providerCredentialLabel(providerKey, credentialKey string) string {
	switch providerKey + ":" + credentialKey {
	case "fofa:email":
		return "FOFA Email"
	case "fofa:key":
		return "FOFA Key"
	default:
		return safeManagementText(credentialKey, 128)
	}
}

func safeCapabilities(values, fallback []string) []string {
	if len(values) == 0 {
		return append([]string{}, fallback...)
	}
	if len(values) > 64 {
		values = values[:64]
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = safeManagementText(value, 64)
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return append([]string{}, fallback...)
	}
	return out
}

func safeMaskedValue(value string) string {
	value = safeManagementText(value, 128)
	if value == maskedSecretPrefix {
		return value
	}
	if strings.HasPrefix(value, maskedSecretPrefix) {
		suffix := []rune(strings.TrimPrefix(value, maskedSecretPrefix))
		if len(suffix) == 4 && !strings.ContainsAny(string(suffix), "•*") {
			return value
		}
		return ""
	}

	const emailMask = "********"
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return ""
	}
	local := value[:at]
	maskAt := strings.Index(local, emailMask)
	if maskAt <= 0 || strings.Count(local, emailMask) != 1 {
		return ""
	}
	prefix := []rune(local[:maskAt])
	suffix := []rune(local[maskAt+len(emailMask):])
	if len(prefix) != 1 || len(suffix) != 1 || strings.ContainsAny(string(append(prefix, suffix...)), "•*@") {
		return ""
	}
	domain := value[at+1:]
	if !validMaskedEmailDomain(domain) {
		return ""
	}
	return value
}

func validMaskedEmailDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safeManagementText(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) {
		return ""
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ""
		}
	}
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return value
}

func elapsedMilliseconds(started, finished time.Time) int64 {
	elapsed := finished.Sub(started).Milliseconds()
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

func managementTimestamp(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func safeManagedBaseURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return parsed.String()
}

type engineCheckCache struct {
	mu    sync.RWMutex
	items map[string]ManagedEngineSummary
}

func (c *engineCheckCache) get(v uint64, route EngineRoute) (ManagedEngineSummary, bool) {
	if c == nil {
		return ManagedEngineSummary{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out, ok := c.items[strconv.FormatUint(v, 10)+":"+string(route)]
	return out, ok
}
func (c *engineCheckCache) put(v uint64, summary ManagedEngineSummary) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) > 64 {
		c.items = make(map[string]ManagedEngineSummary)
	}
	c.items[strconv.FormatUint(v, 10)+":"+string(summary.Route)] = summary
}
func (s *EngineManagementService) WithSettings(store *EngineSettingsStore) *EngineManagementService {
	s.settings = store
	return s
}
func (s *EngineManagementService) resolvedSettings(ctx context.Context) (*EngineManagementService, error) {
	if s.settings == nil {
		return s, nil
	}
	snapshot, err := s.settings.Latest(ctx)
	if err != nil {
		return nil, err
	}
	router, status := snapshot.Router()
	out := *s
	out.settings = nil
	out.version = snapshot.Version
	out.config = snapshot.Settings.RouterConfig()
	out.configStatus = status
	out.policy = snapshot.Settings.Policy
	out.passive = nil
	out.active = nil
	if a, err := router.EngineForTaskType(TaskTypePassiveIntel); err == nil {
		out.passive, _ = a.(passiveEngineInspector)
	}
	if a, err := router.EngineForTaskType(TaskTypePortProbe); err == nil {
		out.active, _ = a.(activeEngineInspector)
	}
	return &out, nil
}
