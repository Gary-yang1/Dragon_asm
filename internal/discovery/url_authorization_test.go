package discovery

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLWildcardAndEffectivePorts(t *testing.T) {
	value, rule, err := normalizeURLAuthorization("https://*.example.com", nil)
	require.NoError(t, err)
	require.Equal(t, "https://example.com", value)
	require.False(t, rule.IncludeRoot)
	require.True(t, rule.IncludeSubdomains)
	target := &ScopeTarget{TargetType: TargetTypeURL, MatchMode: MatchModeInclude, Value: value, URLRule: rule}
	for _, test := range []struct {
		url     string
		allowed bool
	}{
		{"https://api.example.com", true}, {"https://a.b.example.com:443/path?q=1", true},
		{"https://example.com", false}, {"http://api.example.com", false}, {"https://api.example.com:8443", false},
		{"https://notexample.com", false}, {"https://api.example.com.evil.com", false},
	} {
		parsed, err := parseTarget(test.url)
		require.NoError(t, err)
		assert.Equal(t, test.allowed, matchTarget(target, parsed), test.url)
	}
	rule.Protocol = "both"
	rule.IncludeRoot = true
	rule.Ports = []uint16{8443, 443}
	parsed, err := parseTarget("http://example.com:8443")
	require.NoError(t, err)
	require.True(t, matchTarget(target, parsed))
	rule.Ports = nil
	parsed, err = parseTarget("http://api.example.com:80")
	require.NoError(t, err)
	require.True(t, matchTarget(target, parsed))
	parsed, err = parseTarget("https://api.example.com:80")
	require.NoError(t, err)
	require.False(t, matchTarget(target, parsed))
}

func TestURLRulesOverrideBroadDomainGrantsAndInheritance(t *testing.T) {
	svc, repo := inheritanceFixture(t)
	value, rule, err := normalizeURLAuthorization("https://*.example.com", nil)
	require.NoError(t, err)
	repo.targets[1][1] = append(repo.targets[1][1], &ScopeTarget{ID: 90, TargetType: TargetTypeURL, MatchMode: MatchModeInclude, Value: value, URLRule: rule})
	allowed, _, err := svc.IsTypedTargetAllowed(context.Background(), 1, 1, TargetTypeURL, "http://api.example.com")
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, _, err = svc.IsTypedTargetAllowed(context.Background(), 1, 1, TargetTypeURL, "https://api.example.com:443")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, _, err = svc.IsTypedTargetAllowed(context.Background(), 1, 1, TargetTypeURL, "https://excluded.example.com")
	require.NoError(t, err)
	require.False(t, allowed)
	repo.observations[1][7].NormalizedJSON = []byte(`{"asset_type":"web","value":"http://api.example.com"}`)
	page, err := svc.ListDerivedTargets(context.Background(), 1, 10, 0)
	require.NoError(t, err)
	require.Equal(t, "excluded", page.Items[6].Status)
}

func TestURLRuleValidationAndLegacyCompatibility(t *testing.T) {
	for _, raw := range []string{"https://*.*.example.com", "https://*.127.0.0.1", "https://*.com", "ftp://*.example.com", "https://*.example.com/api/*", "https://user:pass@*.example.com"} {
		_, _, err := normalizeURLAuthorization(raw, nil)
		require.Error(t, err, raw)
	}
	_, _, err := normalizeURLAuthorization("https://example.com/admin", &URLAuthorizationRule{Protocol: "https", IncludeRoot: true})
	require.ErrorIs(t, err, ErrInvalidURLAuthorization)
	value, rule, err := normalizeURLAuthorization("https://example.com/admin", nil)
	require.NoError(t, err)
	require.Nil(t, rule)
	require.Equal(t, "https://example.com", value)
	old := &ScopeTarget{TargetType: TargetTypeURL, Value: value}
	explicit, err := parseTarget("https://example.com:443")
	require.NoError(t, err)
	require.False(t, matchTarget(old, explicit), "legacy rules do not expand during migration")
	_, _, err = normalizeURLAuthorization("https://example.com", &URLAuthorizationRule{Protocol: "both", IncludeRoot: true, Ports: []uint16{0}})
	require.Error(t, err)
}

func TestURLSeedsNeverSendWildcardsToEngine(t *testing.T) {
	value, rule, err := normalizeURLAuthorization("https://*.example.com", nil)
	require.NoError(t, err)
	target := &ScopeTarget{TargetType: TargetTypeURL, Value: value, URLRule: rule}
	require.Empty(t, scopeURLSeeds(target))
	rule.IncludeRoot = true
	rule.Protocol = "both"
	rule.Ports = []uint16{8443}
	require.Equal(t, []string{"http://example.com:8443", "https://example.com:8443"}, scopeURLSeeds(target))
}
