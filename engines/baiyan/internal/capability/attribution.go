package capability

import (
	"strings"

	"baiyan/internal/networkenrich"
)

// Attribute keys the passive DNS stage records on host and address facts. They
// are evidence, not decisions: ASM decides what an edge address means for its
// inventory, derived targets and active scanning.
const (
	attrCDNStatus   = "cdn_status"
	attrCDNProvider = "cdn_provider"
	attrCDNEvidence = "cdn_evidence"
	attrRuleVersion = "attribution_rule_version"
	attrIPRole      = "ip_role"
	attrDNSCNAME    = "dns_cname"

	ipRoleCDNEdge = "cdn_edge"
	// maxAttributeValue matches ASM's per-attribute bound.
	maxAttributeValue = 1024
)

// externalAliases returns the aliases of a host that leave every scope root.
// Aliases inside a root are the organisation's own names and become cname_to
// relations instead; an own alias is not evidence of an edge by itself.
func externalAliases(cnames []string, roots map[string]string) []string {
	var out []string
	for _, raw := range cnames {
		if name := normalizeDomain(raw); name != "" && matchingRoot(name, roots) == "" {
			out = append(out, name)
		}
	}
	return out
}

func boundedJoin(values []string, limit int) string {
	joined := ""
	for _, value := range values {
		next := value
		if joined != "" {
			next = joined + "," + value
		}
		if len(next) > limit {
			break
		}
		joined = next
	}
	return joined
}

func annotateCDN(attributes map[string]string, cdn networkenrich.Attribution) {
	attributes[attrCDNStatus] = "identified"
	attributes[attrCDNProvider] = cleanSnapshotText(cdn.Provider, 128)
	attributes[attrCDNEvidence] = cleanSnapshotText(strings.Join(cdn.Evidence, "; "), maxAttributeValue)
	attributes[attrRuleVersion] = networkenrich.RuleVersion
}

// hostAttribution judges one resolved host. aliasEdge is the judgement from
// its external aliases alone: when a name is served through an edge, every
// address it resolves to is that edge, whether or not the range is listed.
func hostAttribution(entry DNSResult, roots map[string]string) (external []string, host, aliasEdge networkenrich.Attribution) {
	external = externalAliases(entry.CNAMEs, roots)
	host, _ = networkenrich.ClassifyNetwork(external, entry.IPs, nil)
	aliasEdge, _ = networkenrich.ClassifyNetwork(external, nil, nil)
	return external, host, aliasEdge
}

// addressAttribution tags one address. A listed range is direct evidence; the
// host's alias judgement is evidence for every address that host resolved to.
func addressAttribution(attributes map[string]string, ip, host string, aliasEdge networkenrich.Attribution) {
	if byRange := networkenrich.ClassifyAddress(ip); byRange.Status == "identified" {
		annotateCDN(attributes, byRange)
		attributes[attrIPRole] = ipRoleCDNEdge
		return
	}
	if aliasEdge.Status == "identified" {
		annotateCDN(attributes, networkenrich.Attribution{
			Status:   "identified",
			Provider: aliasEdge.Provider,
			Evidence: append([]string{"Resolved from " + host + " served by an edge"}, aliasEdge.Evidence...),
		})
		attributes[attrIPRole] = ipRoleCDNEdge
	}
}
