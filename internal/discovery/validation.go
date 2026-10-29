//revive:disable:exported

package discovery

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/netguard"
)

var (
	ErrInvalidProjectID    = errors.New("discovery: invalid project id")
	ErrInvalidName         = errors.New("discovery: invalid name")
	ErrInvalidActorID      = errors.New("discovery: invalid actor id")
	ErrInvalidAuthorizedBy = errors.New("discovery: invalid authorized_by")
	ErrInvalidStatus       = errors.New("discovery: invalid status")
	// ErrScopeWindowTooLong marks an authorisation window beyond MaxScopeWindow.
	ErrScopeWindowTooLong = errors.New("discovery: authorization window exceeds the maximum")
	ErrInvalidTaskType    = errors.New("discovery: invalid task type")
	// ErrTaskTypeUnsupported marks a known task type with no engine implementation.
	// It is distinct from ErrInvalidTaskType so the API can say "not supported yet"
	// rather than "invalid", which is the difference between an operator waiting
	// for a feature and one believing the scan already ran.
	ErrTaskTypeUnsupported    = errors.New("discovery: task type not supported by the configured engine")
	ErrInvalidTaskStatus      = errors.New("discovery: invalid task status")
	ErrInvalidTemplate        = errors.New("discovery: invalid task template")
	ErrInvalidTaskSchedule    = errors.New("discovery: invalid task schedule")
	ErrInvalidTaskLimits      = errors.New("discovery: invalid task limits")
	ErrInvalidTaskConfig      = errors.New("discovery: invalid task config")
	ErrInvalidTemplateID      = errors.New("discovery: invalid template id")
	ErrInvalidTaskRunID       = errors.New("discovery: invalid run id")
	ErrTemplateDisabled       = errors.New("discovery: template disabled")
	ErrTaskRunNotDispatchable = errors.New("discovery: task run not dispatchable")
	ErrDispatchTargetDenied   = errors.New("discovery: dispatch target denied")
	ErrInvalidTargetType      = errors.New("discovery: invalid target type")
	ErrInvalidMatchMode       = errors.New("discovery: invalid match mode")
	ErrInvalidCoverageMode    = errors.New("discovery: invalid coverage mode")
	ErrInvalidDefaultScope    = errors.New("discovery: default scope must be active")
	ErrInvalidScopeID         = errors.New("discovery: invalid scope id")
	ErrInvalidTarget          = errors.New("discovery: invalid target")
	ErrTargetTooLong          = errors.New("discovery: target too long")
	ErrMetadataTooLong        = errors.New("discovery: metadata field too long")
	ErrInvalidTimeRange       = errors.New("discovery: invalid scope window")
	ErrDangerousTarget        = errors.New("discovery: dangerous target")
	ErrDuplicateTargets       = errors.New("discovery: duplicate target")
	ErrInvalidHost            = errors.New("discovery: invalid host")
)

const (
	maxTenantIDLen       = 64
	maxOrgIDLen          = 64
	maxScopeNameLen      = 128
	maxActorLen          = 64
	maxTargetValue       = 512
	maxAuthorizedLen     = 64
	maxDomainLen         = 255
	maxTemplateName      = 128
	maxTemplateConfigLen = 65536
	maxTaskScheduleLen   = 255
)

const (
	httpScheme  = "http"
	httpsScheme = "https"
)

var validStatuses = map[string]bool{
	StatusActive:   true,
	StatusInactive: true,
}

var validTaskTypes = map[string]bool{
	TaskTypeDNS:          true,
	TaskTypeCTLog:        true,
	TaskTypePortProbe:    true,
	TaskTypeWebProbe:     true,
	TaskTypeFingerprint:  true,
	TaskTypeCloudSync:    true,
	TaskTypePassiveIntel: true,
	TaskTypeImport:       true,
	TaskTypeDirScan:      true,
	TaskTypeOrgIntel:     true,
}

var validTaskStatuses = map[string]bool{
	TaskRunStatusPending:   true,
	TaskRunStatusRunning:   true,
	TaskRunStatusSuccess:   true,
	TaskRunStatusPartial:   true,
	TaskRunStatusFailed:    true,
	TaskRunStatusCancelled: true,
}

var validTargetTypes = map[string]bool{
	TargetTypeDomain:  true,
	TargetTypeIP:      true,
	TargetTypeCIDR:    true,
	TargetTypeURL:     true,
	TargetTypeCompany: true,
}

var validMatchModes = map[string]bool{
	MatchModeInclude: true,
	MatchModeExclude: true,
}

func validateScopeMeta(tenantID, orgID, name, authorizedBy, actorID string) error {
	if len(name) == 0 || len(name) > maxScopeNameLen {
		return ErrInvalidName
	}
	if len(tenantID) > maxTenantIDLen {
		return ErrMetadataTooLong
	}
	if len(orgID) > maxOrgIDLen {
		return ErrMetadataTooLong
	}
	if len(authorizedBy) == 0 || len(authorizedBy) > maxAuthorizedLen {
		return ErrInvalidAuthorizedBy
	}
	if len(actorID) == 0 || len(actorID) > maxActorLen {
		return ErrInvalidActorID
	}
	return nil
}

func validateStatus(raw string) (string, error) {
	if raw == "" {
		raw = StatusInactive
	}
	if !validStatuses[raw] {
		return "", ErrInvalidStatus
	}
	return raw, nil
}

// dispatchableTaskTypes is the single definition of task types with an actual
// engine implementation. Active types still require the service-level
// ActiveDispatchPolicy to be explicitly enabled; keeping capability and release
// policy separate lets templates remain fail-closed by default without lying to
// the active adapter about what it can execute.
var dispatchableTaskTypes = map[string]bool{
	TaskTypePassiveIntel: true,
	TaskTypeDNS:          true,
	TaskTypeOrgIntel:     true,
	TaskTypePortProbe:    true,
	TaskTypeWebProbe:     true,
	TaskTypeFingerprint:  true,
}

// IsDispatchableTaskType reports whether the configured engine can run this type.
func IsDispatchableTaskType(v string) bool { return dispatchableTaskTypes[v] }

func validateTaskType(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if !validTaskTypes[v] {
		return "", ErrInvalidTaskType
	}
	if !dispatchableTaskTypes[v] {
		return "", ErrTaskTypeUnsupported
	}
	return v, nil
}

func validateTaskStatus(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if !validTaskStatuses[v] {
		return "", ErrInvalidTaskStatus
	}
	return v, nil
}

func validateTemplateMeta(tenantID, orgID, name string, scopeID, projectID uint64, taskType, actorID string) error {
	if len(name) == 0 || len(name) > maxTemplateName {
		return ErrInvalidName
	}
	if len(tenantID) > maxTenantIDLen || len(orgID) > maxOrgIDLen {
		return ErrMetadataTooLong
	}
	if scopeID == 0 || projectID == 0 {
		return ErrInvalidProjectID
	}
	if _, err := validateTaskType(taskType); err != nil {
		return err
	}
	if len(actorID) == 0 || len(actorID) > maxActorLen {
		return ErrInvalidActorID
	}
	return nil
}

func normalizeTemplateConfig(raw string) (string, error) {
	config := strings.TrimSpace(raw)
	if config == "" {
		return "{}", nil
	}
	if len(config) > maxTemplateConfigLen {
		return "", ErrInvalidTaskConfig
	}
	if !json.Valid([]byte(config)) {
		return "", ErrInvalidTaskConfig
	}
	if err := validateSensitiveConfig(config); err != nil {
		return "", err
	}
	return config, nil
}

func validateTemplateConfig(raw string) error {
	_, err := normalizeTemplateConfig(raw)
	return err
}

type dispatchConfig struct {
	Targets []DispatchTarget
	Options map[string]any
}

type rawDispatchConfig struct {
	Targets []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"targets"`
	Options map[string]any `json:"options"`
}

func parseDispatchConfig(raw string) (dispatchConfig, error) {
	config, err := normalizeTemplateConfig(raw)
	if err != nil {
		return dispatchConfig{}, err
	}

	var parsed rawDispatchConfig
	if err := json.Unmarshal([]byte(config), &parsed); err != nil {
		return dispatchConfig{}, ErrInvalidTaskConfig
	}
	if len(parsed.Targets) == 0 {
		return dispatchConfig{}, ErrInvalidTaskConfig
	}

	out := dispatchConfig{
		Targets: make([]DispatchTarget, 0, len(parsed.Targets)),
		Options: parsed.Options,
	}
	for _, target := range parsed.Targets {
		targetType, err := validateTargetType(target.Type)
		if err != nil {
			return dispatchConfig{}, err
		}
		value, err := normalizeTargetValue(targetType, target.Value)
		if err != nil {
			return dispatchConfig{}, err
		}
		out.Targets = append(out.Targets, DispatchTarget{
			Type:  targetType,
			Value: value,
		})
	}
	if out.Options == nil {
		out.Options = map[string]any{}
	}
	return out, nil
}

func validateTargetType(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if !validTargetTypes[v] {
		return "", ErrInvalidTargetType
	}
	return v, nil
}

func validateTemplateSchedule(raw string) error {
	s := strings.TrimSpace(raw)
	if len(s) > maxTaskScheduleLen {
		return ErrInvalidTaskSchedule
	}
	return nil
}

func validateSensitiveConfig(raw string) error {
	// Inspect decoded JSON, but do not mistake words in validated hostnames
	// (e.g. tokenhub.example.com) for credentials. Keep checking every key,
	// non-target value and URL path/query; only the target hostname is exempt.
	var document map[string]any
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return ErrInvalidTaskConfig
	}
	if targets, ok := document["targets"].([]any); ok {
		for _, entry := range targets {
			target, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			kind, _ := target["type"].(string)
			value, ok := target["value"].(string)
			if !ok {
				continue
			}
			if _, err := normalizeTargetValue(kind, value); err != nil {
				continue
			}
			switch kind {
			case TargetTypeDomain, TargetTypeIP, TargetTypeCIDR:
				target["value"] = "validated-target"
			case TargetTypeURL:
				parsed, err := url.Parse(value)
				if err == nil && parsed.User == nil {
					parsed.Host = "validated-host"
					target["value"] = parsed.String()
				}
			}
		}
	}
	checked, err := json.Marshal(document)
	if err != nil {
		return ErrInvalidTaskConfig
	}
	lower := strings.ToLower(string(checked))
	if strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "cookie") {
		return ErrInvalidTaskConfig
	}
	return nil
}

func validateTaskLimits(timeoutSeconds, rateLimit, concurrency, retryLimit int) error {
	if timeoutSeconds < 1 || timeoutSeconds > 86400 {
		return ErrInvalidTaskLimits
	}
	if rateLimit < 1 || rateLimit > 10000 {
		return ErrInvalidTaskLimits
	}
	if concurrency < 1 || concurrency > 500 {
		return ErrInvalidTaskLimits
	}
	if retryLimit < 0 || retryLimit > 100 {
		return ErrInvalidTaskLimits
	}
	return nil
}

// MaxScopeWindow bounds how long one authorisation can run before it has to be
// renewed. Scanning authorisation is a statement someone made on a date; without
// a ceiling a scope could be authorised until the year 9999 and nobody would ever
// revisit whether the permission still holds.
const MaxScopeWindow = 365 * 24 * time.Hour

func validateScopeWindow(validFrom, validUntil time.Time) error {
	if validFrom.IsZero() || validUntil.IsZero() {
		return ErrInvalidTimeRange
	}
	if validUntil.Before(validFrom) {
		return ErrInvalidTimeRange
	}
	if validUntil.Sub(validFrom) > MaxScopeWindow {
		return ErrScopeWindowTooLong
	}
	return nil
}

func isValidMatchMode(v string) bool {
	return validMatchModes[v]
}

func isValidTargetType(v string) bool {
	return validTargetTypes[v]
}

func validateScopeTargets(inputs []ScopeTargetInput, actorID string) ([]ScopeTarget, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	if len(actorID) == 0 || len(actorID) > maxActorLen {
		return nil, ErrInvalidActorID
	}

	seen := make(map[string]struct{}, len(inputs))
	out := make([]ScopeTarget, 0, len(inputs))
	for _, in := range inputs {
		normalized, err := normalizeScopeTarget(in, actorID)
		if err != nil {
			return nil, err
		}
		k := normalized.TargetType + "|" + normalized.MatchMode + "|" + normalized.Value
		if _, ok := seen[k]; ok {
			return nil, ErrDuplicateTargets
		}
		seen[k] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

func normalizeScopeTarget(in ScopeTargetInput, actorID string) (ScopeTarget, error) {
	if !isValidTargetType(in.TargetType) {
		return ScopeTarget{}, ErrInvalidTargetType
	}
	if !isValidMatchMode(in.MatchMode) {
		return ScopeTarget{}, ErrInvalidMatchMode
	}
	coverageMode := strings.TrimSpace(in.CoverageMode)
	if coverageMode == "" {
		coverageMode = CoverageModeExact
	}
	if coverageMode != CoverageModeExact &&
		(in.TargetType != TargetTypeDomain || coverageMode != CoverageModeSubdomains) {
		return ScopeTarget{}, ErrInvalidCoverageMode
	}

	if in.URLRule != nil && in.TargetType != TargetTypeURL {
		return ScopeTarget{}, ErrInvalidURLAuthorization
	}
	var rule *URLAuthorizationRule
	var value string
	var err error
	if in.TargetType == TargetTypeURL {
		value, rule, err = normalizeURLAuthorization(in.Value, in.URLRule)
	} else {
		value, err = normalizeTargetValue(in.TargetType, in.Value)
	}
	if err != nil {
		return ScopeTarget{}, err
	}

	return ScopeTarget{
		URLRule:      rule,
		TargetType:   in.TargetType,
		MatchMode:    in.MatchMode,
		CoverageMode: coverageMode,
		Value:        value,
		CreatedBy:    actorID,
		UpdatedBy:    actorID,
	}, nil
}

func normalizeTargetValue(targetType, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrInvalidTarget
	}
	if len(raw) > maxTargetValue {
		return "", ErrTargetTooLong
	}

	switch targetType {
	case TargetTypeDomain:
		return normalizeDomain(raw)
	case TargetTypeCompany:
		return normalizeCompanyName(raw)
	case TargetTypeIP:
		addr, err := parseIP(raw)
		if err != nil {
			return "", err
		}
		if isDangerousIP(addr) {
			return "", ErrDangerousTarget
		}
		return addr.String(), nil
	case TargetTypeCIDR:
		pfx, err := parseCIDR(raw)
		if err != nil {
			return "", err
		}
		if isDangerousCIDR(pfx) {
			return "", ErrDangerousTarget
		}
		return pfx.String(), nil
	case TargetTypeURL:
		parsed, err := parseURL(raw)
		if err != nil {
			return "", err
		}
		if isDangerousHost(parsed) {
			return "", ErrDangerousTarget
		}
		return parsed.value, nil
	default:
		return "", ErrInvalidTargetType
	}
}

func normalizeDomain(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimSuffix(value, ".")
	if value == "" || strings.Contains(value, "..") {
		return "", ErrInvalidTarget
	}
	if len(value) > maxDomainLen {
		return "", ErrInvalidTarget
	}
	if isDangerousDomain(value) {
		return "", ErrDangerousTarget
	}

	parts := strings.Split(value, ".")
	for _, p := range parts {
		if err := validateDomainLabel(p); err != nil {
			return "", err
		}
	}

	// A scope target must be a fully qualified, globally resolvable DNS name.
	// This is what keeps non-canonical IP literals out of the domain path: the
	// resolver expands "127.1", "2130706433", "010.0.0.1" and "0" to loopback or
	// RFC1918 addresses, but netip.ParseAddr rejects all of them, so they reach
	// normalizeDomain and would sail past the IP denylist entirely. Rejecting
	// single-label names also stops hex forms ("0x7f000001") and bare internal
	// hostnames ("instance-data", "consul").
	if len(parts) < 2 {
		return "", ErrInvalidTarget
	}
	if isAllDigits(parts[len(parts)-1]) {
		return "", ErrInvalidTarget
	}
	return value, nil
}

func isAllDigits(label string) bool {
	if label == "" {
		return false
	}
	for _, c := range label {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validateDomainLabel(label string) error {
	if label == "" || len(label) > 63 {
		return ErrInvalidTarget
	}
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return ErrInvalidTarget
	}
	for _, c := range label {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return ErrInvalidTarget
	}
	return nil
}

func parseIP(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err == nil {
		if addr.Is4In6() {
			return addr.Unmap(), nil
		}
		return addr, nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		if v, ok := netip.AddrFromSlice(ip); ok {
			return v.Unmap(), nil
		}
	}
	return netip.Addr{}, ErrInvalidTarget
}

func parseCIDR(raw string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, ErrInvalidTarget
	}
	if pfx.Addr().Is4In6() {
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits())
	}
	if !pfx.IsValid() || pfx.Bits() == 0 {
		return netip.Prefix{}, ErrInvalidTarget
	}
	return pfx, nil
}

type parsedTarget struct {
	port    int
	kind    string
	value   string
	scheme  string
	domain  string
	company string
	ip      netip.Addr
}

// parseTypedTarget parses a target whose type the caller already knows.
//
// parseTarget infers the type from the string, which works for addresses but
// cannot work for a company name — that is just text, and guessing would either
// reject it or mistake it for a domain. Everything except company keeps the
// existing inference so behaviour there is unchanged.
func parseTypedTarget(targetType, raw string) (parsedTarget, error) {
	if targetType != TargetTypeCompany {
		return parseTarget(raw)
	}
	company, err := normalizeCompanyName(raw)
	if err != nil {
		return parsedTarget{}, err
	}
	return parsedTarget{kind: TargetTypeCompany, value: company, company: company}, nil
}

func parseTarget(raw string) (parsedTarget, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return parsedTarget{}, ErrInvalidTarget
	}

	if strings.Contains(trimmed, "://") {
		parsed, err := parseURL(trimmed)
		if err != nil {
			return parsedTarget{}, err
		}
		if isDangerousHost(parsed) {
			return parsedTarget{}, ErrDangerousTarget
		}
		return parsed, nil
	}

	if ip, err := parseIP(trimmed); err == nil {
		if isDangerousIP(ip) {
			return parsedTarget{}, ErrDangerousTarget
		}
		return parsedTarget{kind: TargetTypeIP, value: ip.String(), ip: ip}, nil
	}

	if pfx, err := parseCIDR(trimmed); err == nil {
		if isDangerousCIDR(pfx) {
			return parsedTarget{}, ErrDangerousTarget
		}
		return parsedTarget{kind: TargetTypeCIDR, value: pfx.String(), ip: pfx.Addr()}, nil
	}

	domain, err := normalizeDomain(trimmed)
	if err != nil {
		return parsedTarget{}, err
	}
	return parsedTarget{kind: TargetTypeDomain, value: domain, domain: domain}, nil
}

func parseURL(raw string) (parsedTarget, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return parsedTarget{}, ErrInvalidTarget
	}
	if u.Scheme != httpScheme && u.Scheme != httpsScheme {
		return parsedTarget{}, ErrInvalidTarget
	}

	host := strings.TrimSpace(strings.ToLower(u.Hostname()))
	if host == "" {
		return parsedTarget{}, ErrInvalidHost
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return parsedTarget{}, ErrInvalidHost
	}

	if port := strings.TrimSpace(u.Port()); port != "" {
		p, perr := strconv.Atoi(port)
		if perr != nil || p <= 0 || p > 65535 {
			return parsedTarget{}, ErrInvalidTarget
		}
	}

	parsed := parsedTarget{
		kind:   TargetTypeURL,
		scheme: u.Scheme,
	}
	if u.Port() != "" {
		parsed.port, _ = strconv.Atoi(u.Port())
	}
	if ip, err := parseIP(host); err == nil {
		parsed.ip = ip
		parsed.domain = ip.String()
	} else {
		domain, err := normalizeDomain(host)
		if err != nil {
			return parsedTarget{}, err
		}
		parsed.domain = domain
	}

	parsed.value = u.Scheme + "://" + parsed.domain
	if port := strings.TrimSpace(u.Port()); port != "" {
		parsed.value += ":" + port
	}
	return parsed, nil
}

func isDangerousHost(p parsedTarget) bool {
	if p.ip.IsValid() {
		return isDangerousIP(p.ip)
	}
	if p.domain == "" {
		return true
	}
	return isDangerousDomain(p.domain)
}

// specialUseDomainSuffixes are names reserved by the IETF/ICANN for local or
// non-resolvable use. They are never a legitimate external attack surface, and
// several resolve to infrastructure a scan must never reach — ".internal" in
// particular covers metadata.google.internal.
//
// Names in common private use but not reserved (".corp", ".lan", ".intranet")
// are deliberately absent: an operator inventorying an internal estate has a
// legitimate need for them, and the reserved list above is the defensible floor.
var specialUseDomainSuffixes = []string{
	".localhost",
	".local",
	".localdomain",
	".internal",
	".home.arpa",
	".alt",
	".invalid",
	".test",
	".example",
}

func isDangerousDomain(raw string) bool {
	v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if v == "localhost" {
		return true
	}
	for _, suffix := range specialUseDomainSuffixes {
		if strings.HasSuffix(v, suffix) {
			return true
		}
	}
	return false
}

// isDangerousCIDR and isDangerousIP delegate to platform/netguard so the scan
// denylist and the outbound-HTTP denylist can never drift apart.
func isDangerousCIDR(prefix netip.Prefix) bool {
	return netguard.IsDangerousPrefix(prefix)
}

func isDangerousIP(addr netip.Addr) bool {
	return netguard.IsDangerousAddr(addr)
}

func parseScopeTargetForMatch(raw ScopeTarget) (parsedTarget, error) {
	s := parsedTarget{kind: raw.TargetType, value: raw.Value}
	switch raw.TargetType {
	case TargetTypeCompany:
		company, err := normalizeCompanyName(raw.Value)
		if err != nil {
			return parsedTarget{}, err
		}
		s.company = company
	case TargetTypeDomain:
		domain, err := normalizeDomain(raw.Value)
		if err != nil {
			return parsedTarget{}, err
		}
		s.domain = domain
	case TargetTypeIP:
		ip, err := parseIP(raw.Value)
		if err != nil {
			return parsedTarget{}, err
		}
		s.ip = ip
		s.domain = ip.String()
	case TargetTypeCIDR:
		p, err := parseCIDR(raw.Value)
		if err != nil {
			return parsedTarget{}, err
		}
		s.ip = p.Addr()
		s.value = p.String()
	case TargetTypeURL:
		parsed, err := parseURL(raw.Value)
		if err != nil {
			return parsedTarget{}, err
		}
		s = parsed
	default:
		return parsedTarget{}, ErrInvalidTargetType
	}
	return s, nil
}

func matchTarget(target *ScopeTarget, candidate parsedTarget) bool {
	if target == nil {
		return false
	}
	if target.TargetType == TargetTypeURL && target.URLRule != nil {
		return matchURLAuthorization(target, candidate)
	}
	t, err := parseScopeTargetForMatch(*target)
	if err != nil {
		return false
	}

	switch target.TargetType {
	case TargetTypeCompany:
		// Legal names are matched exactly. A prefix or substring rule would let a
		// scope authorising one company reach an unrelated one that happens to
		// share a name fragment, which is common in Chinese company names.
		return candidate.company != "" && t.company == candidate.company
	case TargetTypeDomain:
		if candidate.domain == "" {
			return false
		}
		if strings.EqualFold(t.domain, candidate.domain) {
			return true
		}
		return target.CoverageMode == CoverageModeSubdomains &&
			strings.HasSuffix(strings.ToLower(candidate.domain), "."+strings.ToLower(t.domain))
	case TargetTypeIP:
		return candidate.ip.IsValid() && t.ip == candidate.ip
	case TargetTypeCIDR:
		if !candidate.ip.IsValid() {
			return false
		}
		p, err := parseCIDR(t.value)
		if err != nil {
			return false
		}
		return p.Contains(candidate.ip)
	case TargetTypeURL:
		return candidate.value != "" && t.value == candidate.value
	default:
		return false
	}
}

// maxCompanyNameLen bounds a registered legal name. The longest Chinese company
// names run well under this; anything longer is not a company name.
const maxCompanyNameLen = 200

// normalizeCompanyName accepts a registered legal entity name.
//
// It is not an address and is never resolved or connected to, so the checks are
// about keeping junk out of the database and out of a tool's argv rather than
// about network safety: no control characters, no leading dash that could be
// read as a flag downstream, and a bounded length.
func normalizeCompanyName(raw string) (string, error) {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, raw)
	cleaned = strings.TrimSpace(strings.ReplaceAll(cleaned, "　", " "))
	if cleaned == "" || utf8.RuneCountInString(cleaned) > maxCompanyNameLen {
		return "", ErrInvalidTarget
	}
	if strings.HasPrefix(cleaned, "-") {
		return "", ErrInvalidTarget
	}
	return cleaned, nil
}
