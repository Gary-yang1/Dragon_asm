package netguard_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/netguard"
)

// This list is the platform's single definition of "must not be reached". Both
// the scan-scope validator and the outbound webhook client consult it, so a gap
// here is a gap in two subsystems at once.
func TestIsDangerousAddr(t *testing.T) {
	blocked := []string{
		"127.0.0.1",        // loopback
		"127.1.2.3",        // anywhere in 127/8
		"10.0.0.1",         // RFC1918
		"172.16.0.1",       // RFC1918
		"192.168.1.1",      // RFC1918
		"169.254.169.254",  // cloud metadata
		"169.254.1.1",      // link-local generally
		"0.0.0.0",          // unspecified
		"100.64.0.1",       // CGNAT
		"192.0.2.1",        // TEST-NET-1
		"198.18.0.1",       // benchmarking
		"224.0.0.1",        // multicast
		"255.255.255.255",  // broadcast
		"::1",              // IPv6 loopback
		"fc00::1",          // unique local
		"fe80::1",          // IPv6 link-local
		"ff02::1",          // IPv6 multicast
		"::ffff:127.0.0.1", // IPv4-mapped loopback
		"::127.0.0.1",      // IPv4-compatible loopback
		"64:ff9b::7f00:1",  // NAT64-embedded loopback
		"64:ff9b:1::a00:1", // NAT64 local-use with RFC1918 inside
		"2002:7f00:1::",    // 6to4-embedded loopback
		"2001:0:1::",       // Teredo
		"100::1",           // discard-only
		"2001:db8::1",      // documentation
	}
	for _, raw := range blocked {
		t.Run("blocked/"+raw, func(t *testing.T) {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				t.Fatalf("parse %q: %v", raw, err)
			}
			assert.True(t, netguard.IsDangerousAddr(addr), "%s must be blocked", raw)
		})
	}

	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"2606:4700:4700::1111",
	}
	for _, raw := range allowed {
		t.Run("allowed/"+raw, func(t *testing.T) {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				t.Fatalf("parse %q: %v", raw, err)
			}
			assert.False(t, netguard.IsDangerousAddr(addr), "%s is public and must be allowed", raw)
		})
	}
}

// An invalid address must fail closed rather than being treated as public.
func TestIsDangerousAddrRejectsZeroValue(t *testing.T) {
	assert.True(t, netguard.IsDangerousAddr(netip.Addr{}))
}

// A prefix is refused when it touches reserved space at all: authorising a wide
// CIDR must not become a licence to reach loopback inside it.
func TestIsDangerousPrefix(t *testing.T) {
	blocked := []string{
		"10.0.0.0/8",
		"127.0.0.0/8",
		"0.0.0.0/0", // covers everything, including loopback
		"1.0.0.0/1", // overlaps 100.64/10 and other reserved v4 space
		"fc00::/7",
		"::/0",
	}
	for _, raw := range blocked {
		t.Run("blocked/"+raw, func(t *testing.T) {
			assert.True(t, netguard.IsDangerousPrefix(netip.MustParsePrefix(raw)), "%s must be blocked", raw)
		})
	}

	allowed := []string{
		"1.1.1.1/32",
		"93.184.216.0/24",
		"2606:4700:4700::/48",
	}
	for _, raw := range allowed {
		t.Run("allowed/"+raw, func(t *testing.T) {
			assert.False(t, netguard.IsDangerousPrefix(netip.MustParsePrefix(raw)), "%s must be allowed", raw)
		})
	}
}
