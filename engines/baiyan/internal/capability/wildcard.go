package capability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sort"
	"strings"
)

const (
	// wildcardProbesPerZone random names must all resolve before a zone is
	// treated as wildcarded; one stray answer is not enough.
	wildcardProbesPerZone = 2
	// maxWildcardZones bounds the extra DNS work one job spends on probing.
	// Zones beyond it are resolved normally, without wildcard filtering.
	maxWildcardZones = 200
)

// wildcardAnswer is what a zone's wildcard record resolves to.
type wildcardAnswer struct {
	ips    map[string]bool
	cnames map[string]bool
}

func randomDNSLabel() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	// A leading letter keeps the label valid for resolvers that reject
	// all-numeric labels.
	return "w" + hex.EncodeToString(buf)
}

// parentZone is the name a wildcard record would have to sit on to answer for
// host: "a.b.example.com" is answered by "*.b.example.com". A wildcard higher up
// (*.example.com) also answers random names under b.example.com unless that
// name exists, so probing the immediate parent covers both.
func parentZone(host string) string {
	if index := strings.IndexByte(host, '.'); index > 0 {
		return host[index+1:]
	}
	return ""
}

// detectWildcards resolves random names under the parent zone of each host and
// returns the answers of zones where every probe resolved. Probing failures are
// not errors: a zone that cannot be probed is simply not filtered.
func (e *PassiveExecutor) detectWildcards(ctx context.Context, hosts []string, roots map[string]string, concurrency, batchSize int, gate operationGate) map[string]wildcardAnswer {
	zoneSet := map[string]bool{}
	for _, host := range hosts {
		zone := parentZone(host)
		if zone == "" || !strings.Contains(zone, ".") || matchingRoot(zone, roots) == "" {
			continue
		}
		zoneSet[zone] = true
	}
	zones := make([]string, 0, len(zoneSet))
	for zone := range zoneSet {
		zones = append(zones, zone)
	}
	sort.Strings(zones)
	if len(zones) > maxWildcardZones {
		zones = zones[:maxWildcardZones]
	}

	probeZone := map[string]string{}
	probes := make([]string, 0, len(zones)*wildcardProbesPerZone)
	for _, zone := range zones {
		for i := 0; i < wildcardProbesPerZone; i++ {
			label := e.randomLabel()
			if label == "" {
				return nil
			}
			name := label + "." + zone
			probeZone[name] = zone
			probes = append(probes, name)
		}
	}

	answered := map[string]int{}
	answers := map[string]wildcardAnswer{}
	for start := 0; start < len(probes); start += batchSize {
		end := min(start+batchSize, len(probes))
		// A partial failure only means some zones stay unfiltered.
		resolved, _ := e.resolver.Resolve(ctx, probes[start:end], concurrency, gate)
		if ctx.Err() != nil {
			return nil
		}
		for _, entry := range resolved {
			zone, ok := probeZone[normalizeDomain(entry.Host)]
			if !ok || entry.Status != "success" || len(entry.IPs) == 0 && len(entry.CNAMEs) == 0 {
				continue
			}
			answer, exists := answers[zone]
			if !exists {
				answer = wildcardAnswer{ips: map[string]bool{}, cnames: map[string]bool{}}
				answers[zone] = answer
			}
			answered[zone]++
			for _, raw := range entry.IPs {
				if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
					answer.ips[ip.String()] = true
				}
			}
			for _, raw := range entry.CNAMEs {
				if name := normalizeDomain(raw); name != "" {
					answer.cnames[name] = true
				}
			}
		}
	}
	for zone := range answers {
		if answered[zone] < wildcardProbesPerZone {
			delete(answers, zone)
		}
	}
	return answers
}

// matchesWildcard reports whether a host's answer is indistinguishable from its
// zone's wildcard: every address (or, with no address, every alias) it resolved
// to is one the random names also got. A host with an answer of its own — even
// one address outside the wildcard set — is a real record and is kept.
func (w wildcardAnswer) matchesWildcard(entry DNSResult) bool {
	if len(entry.IPs) > 0 {
		for _, raw := range entry.IPs {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil || !w.ips[ip.String()] {
				return false
			}
		}
		return true
	}
	if len(entry.CNAMEs) == 0 {
		return false
	}
	for _, raw := range entry.CNAMEs {
		if !w.cnames[normalizeDomain(raw)] {
			return false
		}
	}
	return true
}
