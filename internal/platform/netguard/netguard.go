// Package netguard is the single source of truth for "may this platform talk to
// that address".
//
// Two subsystems need the same answer: discovery, which must refuse to scan
// internal space, and any outbound client that follows an operator-supplied URL
// (notification webhooks). Keeping one list here stops the two denylists from
// drifting apart — a gap in either one is a way out of the network.
package netguard

import "net/netip"

// IsDangerousAddr reports whether addr is anything other than a routable public
// host: loopback, private, link-local (which covers the cloud metadata service),
// multicast, unspecified, or a reserved/transition range.
func IsDangerousAddr(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	// Global-unicast excludes link-local and private for both v4 and v6 in practice.
	if !addr.IsGlobalUnicast() {
		return true
	}
	if addr == cloudMetadataIPv4 {
		return true
	}
	for _, r := range ReservedV4 {
		if r.Addr().Is4() && addr.Is4() && r.Contains(addr) {
			return true
		}
	}
	for _, r := range ReservedV6 {
		if r.Addr().Is6() && addr.Is6() && r.Contains(addr) {
			return true
		}
	}
	return false
}

// IsDangerousPrefix reports whether a CIDR touches any blocked range at all.
// A prefix that merely overlaps reserved space is rejected: authorising
// 0.0.0.0/0 must not become a licence to scan loopback.
func IsDangerousPrefix(prefix netip.Prefix) bool {
	if IsDangerousAddr(prefix.Addr()) {
		return true
	}
	for _, r := range ReservedV4 {
		if prefix.Overlaps(r) {
			return true
		}
	}
	for _, r := range ReservedV6 {
		if prefix.Overlaps(r) {
			return true
		}
	}
	return false
}

// ReservedV4 are IPv4 ranges that must never be reached.
var ReservedV4 = []netip.Prefix{
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

// ReservedV6 are IPv6 ranges that must never be reached. The transition ranges
// matter as much as the obvious ones: each embeds an IPv4 address inside an
// otherwise global-unicast IPv6 address, so without them 64:ff9b::7f00:1 (NAT64
// loopback) and 2002:7f00:1:: (6to4 loopback) look public.
var ReservedV6 = []netip.Prefix{
	mustPrefix("::/128"),
	mustPrefix("::1/128"),
	mustPrefix("fc00::/7"),
	mustPrefix("fe80::/10"),
	mustPrefix("ff00::/8"),
	mustPrefix("2001:db8::/32"),
	mustPrefix("::/96"),          // IPv4-compatible (deprecated), e.g. ::127.0.0.1
	mustPrefix("64:ff9b::/96"),   // NAT64 well-known prefix (RFC 6052)
	mustPrefix("64:ff9b:1::/48"), // NAT64 local-use prefix (RFC 8215)
	mustPrefix("2002::/16"),      // 6to4 (RFC 3056)
	mustPrefix("2001::/32"),      // Teredo (RFC 4380)
	mustPrefix("100::/64"),       // discard-only (RFC 6666)
}

var cloudMetadataIPv4 = netip.MustParseAddr("169.254.169.254")

func mustPrefix(v string) netip.Prefix {
	return netip.MustParsePrefix(v)
}
