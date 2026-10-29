package discovery

import (
	"errors"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// ErrInvalidURLAuthorization rejects ambiguous or unsupported site rules.
var ErrInvalidURLAuthorization = errors.New("discovery: invalid URL authorization rule")

const reasonURLRestricted ScopeRejectReason = "URL_RULE_RESTRICTED"

// Explicit site rules take precedence over broad domain/IP grants for the
// same host family. Exclusions always win; unrelated legacy grants stay intact.
func scopeMatchDecision(targets []*ScopeTarget, candidate parsedTarget) ScopeRejectReason {
	specialized := false
	for _, target := range targets {
		if target.MatchMode == MatchModeExclude && matchTarget(target, candidate) {
			return ReasonExcluded
		}
		if target.MatchMode != MatchModeInclude || target.URLRule == nil || candidate.kind != TargetTypeURL {
			continue
		}
		u, err := url.Parse(target.Value)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if host != "" && (host == candidate.domain || strings.HasSuffix(candidate.domain, "."+host)) {
			specialized = true
		}
	}
	for _, target := range targets {
		if target.MatchMode != MatchModeInclude || (specialized && target.TargetType != TargetTypeURL) {
			continue
		}
		if matchTarget(target, candidate) {
			return ReasonAllowed
		}
	}
	if specialized {
		return reasonURLRestricted
	}
	return ReasonNoMatch
}

// URLAuthorizationRule restricts a whole-site authorization by hostname,
// protocol and effective port. Empty Ports means each protocol's default port.
type URLAuthorizationRule struct {
	Protocol          string   `json:"protocol"`
	IncludeSubdomains bool     `json:"include_subdomains"`
	IncludeRoot       bool     `json:"include_root"`
	Ports             []uint16 `json:"ports"`
}

func normalizeURLAuthorization(raw string, input *URLAuthorizationRule) (string, *URLAuthorizationRule, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > maxTargetValue {
		return "", nil, ErrInvalidURLAuthorization
	}
	if input != nil && !strings.Contains(raw, "://") {
		scheme := "https"
		if input.Protocol == "http" {
			scheme = "http"
		}
		raw = scheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, ErrInvalidURLAuthorization
	}
	wildcard := strings.HasPrefix(u.Hostname(), "*.")
	if input == nil && !wildcard {
		value, err := normalizeTargetValue(TargetTypeURL, raw)
		return value, nil, err
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", nil, ErrInvalidURLAuthorization
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", nil, ErrInvalidURLAuthorization
	}
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p < 1 || p > 65535 {
			return "", nil, ErrInvalidURLAuthorization
		}
	}
	rule := URLAuthorizationRule{Protocol: u.Scheme, IncludeRoot: !wildcard, IncludeSubdomains: wildcard, Ports: []uint16{}}
	if input != nil {
		rule = *input
		rule.Ports = append([]uint16{}, input.Ports...)
	}
	if wildcard {
		rule.IncludeSubdomains = true
	}
	if rule.Protocol != "http" && rule.Protocol != "https" && rule.Protocol != "both" {
		return "", nil, ErrInvalidURLAuthorization
	}
	if !rule.IncludeRoot && !rule.IncludeSubdomains {
		return "", nil, ErrInvalidURLAuthorization
	}
	host := strings.TrimPrefix(u.Hostname(), "*.")
	if strings.Contains(host, "*") {
		return "", nil, ErrInvalidURLAuthorization
	}
	if ip, err := parseIP(host); err == nil {
		if rule.IncludeSubdomains || isDangerousIP(ip) {
			return "", nil, ErrInvalidURLAuthorization
		}
		host = ip.String()
	} else {
		host, err = normalizeDomain(host)
		if err != nil {
			return "", nil, ErrInvalidURLAuthorization
		}
	}
	if input == nil && u.Port() != "" {
		p, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || p == 0 {
			return "", nil, ErrInvalidURLAuthorization
		}
		rule.Ports = []uint16{uint16(p)}
	}
	if len(rule.Ports) > 20 {
		return "", nil, ErrInvalidURLAuthorization
	}
	sort.Slice(rule.Ports, func(i, j int) bool { return rule.Ports[i] < rule.Ports[j] })
	ports := []uint16{}
	for _, p := range rule.Ports {
		if p == 0 {
			return "", nil, ErrInvalidURLAuthorization
		}
		if len(ports) == 0 || ports[len(ports)-1] != p {
			ports = append(ports, p)
		}
	}
	rule.Ports = ports
	scheme := "https"
	if rule.Protocol == "http" {
		scheme = "http"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, &rule, nil
}

func matchURLAuthorization(target *ScopeTarget, candidate parsedTarget) bool {
	if candidate.kind != TargetTypeURL || target.URLRule == nil {
		return false
	}
	_, rule, err := normalizeURLAuthorization(target.Value, target.URLRule)
	if err != nil {
		return false
	}
	anchor, err := url.Parse(target.Value)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(anchor.Hostname(), "."))
	exact := strings.EqualFold(host, candidate.domain)
	if exact && !rule.IncludeRoot {
		return false
	}
	if !exact && (!rule.IncludeSubdomains || !strings.HasSuffix(strings.ToLower(candidate.domain), "."+host)) {
		return false
	}
	if rule.Protocol != "both" && candidate.scheme != rule.Protocol {
		return false
	}
	port := candidate.port
	if port == 0 {
		if candidate.scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	if len(rule.Ports) == 0 {
		return (candidate.scheme == "https" && port == 443) || (candidate.scheme == "http" && port == 80)
	}
	for _, allowed := range rule.Ports {
		if int(allowed) == port {
			return true
		}
	}
	return false
}

// scopeURLSeeds expands only concrete root hosts. Wildcard-only scopes must
// obtain concrete URLs from discovery evidence rather than scan a wildcard.
func scopeURLSeeds(target *ScopeTarget) []string {
	if target.URLRule == nil {
		return []string{target.Value}
	}
	_, rule, err := normalizeURLAuthorization(target.Value, target.URLRule)
	if err != nil || !rule.IncludeRoot {
		return nil
	}
	u, err := url.Parse(target.Value)
	if err != nil {
		return nil
	}
	protocols := []string{rule.Protocol}
	if rule.Protocol == "both" {
		protocols = []string{"http", "https"}
	}
	values := []string{}
	for _, protocol := range protocols {
		ports := rule.Ports
		if len(ports) == 0 {
			if protocol == "https" {
				ports = []uint16{443}
			} else {
				ports = []uint16{80}
			}
		}
		for _, port := range ports {
			values = append(values, protocol+"://"+net.JoinHostPort(u.Hostname(), strconv.Itoa(int(port))))
		}
	}
	return values
}
