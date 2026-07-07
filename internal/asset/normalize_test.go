package asset_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
)

// Acceptance: valid inputs normalize to a stable, type-prefixed key, and inputs
// that differ only by case/trailing dot/whitespace/IPv6-form collapse to the
// same key (the basis of import idempotency).
func TestNormalizeValid(t *testing.T) {
	cases := []struct {
		name      string
		assetType string
		in        string
		wantKey   string
		wantValue string
	}{
		{"domain lowercased", asset.TypeDomain, "Example.COM", "domain:example.com", "example.com"},
		{"domain trailing dot", asset.TypeDomain, "example.com.", "domain:example.com", "example.com"},
		{"domain padded", asset.TypeDomain, "  example.com  ", "domain:example.com", "example.com"},
		{"subdomain", asset.TypeSubdomain, "API.Example.com", "subdomain:api.example.com", "api.example.com"},
		{"ipv4", asset.TypeIP, "192.168.1.1", "ip:192.168.1.1", "192.168.1.1"},
		{"ipv6 compressed", asset.TypeIP, "2001:0db8:0000:0000:0000:0000:0000:0001", "ip:2001:db8::1", "2001:db8::1"},
		{"port ipv4", asset.TypePort, "192.168.1.1:443", "port:192.168.1.1:443", "192.168.1.1:443"},
		{"port ipv6", asset.TypePort, "[2001:db8::1]:8080", "port:[2001:db8::1]:8080", "[2001:db8::1]:8080"},
		{"web passthrough", asset.TypeWeb, "https://example.com/app", "web:https://example.com/app", "https://example.com/app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := asset.Normalize(tc.assetType, tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.wantKey, n.Key)
			assert.Equal(t, tc.wantValue, n.Value)
		})
	}
}

// Acceptance: illegal domain/ip/port and empty/unknown inputs are rejected with
// the matching typed error.
func TestNormalizeInvalid(t *testing.T) {
	cases := []struct {
		name      string
		assetType string
		in        string
		wantErr   error
	}{
		{"unknown type", "bogus", "x", asset.ErrInvalidType},
		{"empty value", asset.TypeDomain, "   ", asset.ErrEmptyValue},
		{"bad domain space", asset.TypeDomain, "exa mple.com", asset.ErrInvalidDomain},
		{"bad domain underscore", asset.TypeDomain, "_dmarc..com", asset.ErrInvalidDomain},
		{"bad domain empty label", asset.TypeDomain, "example..com", asset.ErrInvalidDomain},
		{"bad ip", asset.TypeIP, "999.999.1.1", asset.ErrInvalidIP},
		{"ip leading zeros rejected", asset.TypeIP, "192.168.000.1", asset.ErrInvalidIP},
		{"ip not a domain", asset.TypeIP, "example.com", asset.ErrInvalidIP},
		{"port missing", asset.TypePort, "192.168.1.1", asset.ErrInvalidPort},
		{"port zero", asset.TypePort, "192.168.1.1:0", asset.ErrInvalidPort},
		{"port too big", asset.TypePort, "192.168.1.1:70000", asset.ErrInvalidPort},
		{"port host not ip", asset.TypePort, "example.com:443", asset.ErrInvalidIP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := asset.Normalize(tc.assetType, tc.in)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}
