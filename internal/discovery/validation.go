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
)

var (
	ErrInvalidProjectID    = errors.New("discovery: invalid project id")
	ErrInvalidName         = errors.New("discovery: invalid name")
	ErrInvalidActorID      = errors.New("discovery: invalid actor id")
	ErrInvalidAuthorizedBy = errors.New("discovery: invalid authorized_by")
	ErrInvalidStatus       = errors.New("discovery: invalid status")
	ErrInvalidTaskType     = errors.New("discovery: invalid task type")
	ErrInvalidTaskStatus   = errors.New("discovery: invalid task status")
	ErrInvalidTemplate     = errors.New("discovery: invalid task template")
	ErrInvalidTaskSchedule = errors.New("discovery: invalid task schedule")
	ErrInvalidTaskLimits   = errors.New("discovery: invalid task limits")
	ErrInvalidTaskConfig   = errors.New("discovery: invalid task config")
	ErrInvalidTemplateID   = errors.New("discovery: invalid template id")
	ErrInvalidTaskRunID    = errors.New("discovery: invalid run id")
	ErrTemplateDisabled    = errors.New("discovery: template disabled")
	ErrInvalidTargetType   = errors.New("discovery: invalid target type")
	ErrInvalidMatchMode    = errors.New("discovery: invalid match mode")
	ErrInvalidScopeID      = errors.New("discovery: invalid scope id")
	ErrInvalidTarget       = errors.New("discovery: invalid target")
	ErrTargetTooLong       = errors.New("discovery: target too long")
	ErrMetadataTooLong     = errors.New("discovery: metadata field too long")
	ErrInvalidTimeRange    = errors.New("discovery: invalid scope window")
	ErrDangerousTarget     = errors.New("discovery: dangerous target")
	ErrDuplicateTargets    = errors.New("discovery: duplicate target")
	ErrInvalidHost         = errors.New("discovery: invalid host")
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
	maxTemplateConfigLen = 8192
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
	TargetTypeDomain: true,
	TargetTypeIP:     true,
	TargetTypeCIDR:   true,
	TargetTypeURL:    true,
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

func validateTaskType(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if !validTaskTypes[v] {
		return "", ErrInvalidTaskType
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

func validateTemplateSchedule(raw string) error {
	s := strings.TrimSpace(raw)
	if len(s) > maxTaskScheduleLen {
		return ErrInvalidTaskSchedule
	}
	return nil
}

func validateSensitiveConfig(raw string) error {
	lower := strings.ToLower(strings.TrimSpace(raw))
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

func validateScopeWindow(validFrom, validUntil time.Time) error {
	if validFrom.IsZero() || validUntil.IsZero() {
		return ErrInvalidTimeRange
	}
	if validUntil.Before(validFrom) {
		return ErrInvalidTimeRange
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

	value, err := normalizeTargetValue(in.TargetType, in.Value)
	if err != nil {
		return ScopeTarget{}, err
	}

	return ScopeTarget{
		TargetType: in.TargetType,
		MatchMode:  in.MatchMode,
		Value:      value,
		CreatedBy:  actorID,
		UpdatedBy:  actorID,
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
	return value, nil
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
	kind   string
	value  string
	scheme string
	domain string
	ip     netip.Addr
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

func isDangerousDomain(raw string) bool {
	v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	return v == "localhost" || strings.HasSuffix(v, ".localhost")
}

func isDangerousCIDR(prefix netip.Prefix) bool {
	if isDangerousIP(prefix.Addr()) {
		return true
	}
	for _, r := range reservedCIDRsV4 {
		if prefix.Overlaps(r) {
			return true
		}
	}
	for _, r := range reservedCIDRsV6 {
		if prefix.Overlaps(r) {
			return true
		}
	}
	return false
}

func isDangerousIP(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	// global- unicast excludes link-local and private for both v4/v6 in practice.
	if !addr.IsGlobalUnicast() {
		return true
	}
	if isCloudMetadata(addr) {
		return true
	}

	for _, r := range reservedCIDRsV4 {
		if r.Addr().Is4() && addr.Is4() && r.Contains(addr) {
			return true
		}
	}
	for _, r := range reservedCIDRsV6 {
		if r.Addr().Is6() && addr.Is6() && r.Contains(addr) {
			return true
		}
	}
	return false
}

var reservedCIDRsV4 = []netip.Prefix{
	mustPrefix("0.0.0.0/8"),
	mustPrefix("10.0.0.0/8"),
	mustPrefix("100.64.0.0/10"),
	mustPrefix("127.0.0.0/8"),
	mustPrefix("169.254.0.0/16"),
	mustPrefix("172.16.0.0/12"),
	mustPrefix("192.0.0.0/24"),
	mustPrefix("192.168.0.0/16"),
	mustPrefix("198.18.0.0/15"),
	mustPrefix("192.0.2.0/24"),
	mustPrefix("198.51.100.0/24"),
	mustPrefix("203.0.113.0/24"),
	mustPrefix("240.0.0.0/4"),
	mustPrefix("255.255.255.255/32"),
}

var reservedCIDRsV6 = []netip.Prefix{
	mustPrefix("::/128"),
	mustPrefix("::1/128"),
	mustPrefix("fc00::/7"),
	mustPrefix("fe80::/10"),
	mustPrefix("ff00::/8"),
	mustPrefix("2001:db8::/32"),
}

var cloudMetadataIPv4 = netip.MustParseAddr("169.254.169.254")

func parseScopeTargetForMatch(raw ScopeTarget) (parsedTarget, error) {
	s := parsedTarget{kind: raw.TargetType, value: raw.Value}
	switch raw.TargetType {
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
	t, err := parseScopeTargetForMatch(*target)
	if err != nil {
		return false
	}

	switch target.TargetType {
	case TargetTypeDomain:
		return candidate.domain != "" && strings.EqualFold(t.domain, candidate.domain)
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

func mustPrefix(v string) netip.Prefix {
	p, err := netip.ParsePrefix(v)
	if err != nil {
		panic(err)
	}
	return p
}

func isCloudMetadata(addr netip.Addr) bool {
	return addr == cloudMetadataIPv4
}
