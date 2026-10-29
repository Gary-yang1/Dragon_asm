package capability

import (
	"testing"

	"baiyan/internal/contract"
	"baiyan/internal/networkenrich"
)

func dnsAddressFact(assets []contract.AssetFact, ip string) *contract.AssetFact {
	for i := range assets {
		if assets[i].AssetType == "ip" && assets[i].Value == ip {
			return &assets[i]
		}
	}
	return nil
}

func TestDNSStageRecordsEdgeEvidenceOnHostsAndAddresses(t *testing.T) {
	resolver := &zoneResolver{records: map[string]DNSResult{
		// Served through Cloudflare by alias; the address is not in a listed range.
		"shop.example.com": {Status: "success", IPs: []string{"198.51.100.7"}, CNAMEs: []string{"shop.example.com.cdn.cloudflare.net"}},
		// Same address seen first from a host with no alias evidence.
		"aaa.example.com": {Status: "success", IPs: []string{"198.51.100.7"}},
		// A listed Cloudflare range, no alias.
		"api.example.com": {Status: "success", IPs: []string{"104.16.1.1"}},
		// Alias to the organisation's own name: a relation, not edge evidence.
		"www.example.com": {Status: "success", IPs: []string{"192.0.2.5"}, CNAMEs: []string{"origin.example.com"}},
	}}
	assets, relations, _ := runWildcardJob(t, resolver, []string{"aaa.example.com", "shop.example.com", "api.example.com", "www.example.com"})

	shop := dnsFact(assets, "shop.example.com")
	if shop == nil || shop.Attributes[attrCDNStatus] != "identified" || shop.Attributes[attrCDNProvider] != "Cloudflare" ||
		shop.Attributes[attrDNSCNAME] != "shop.example.com.cdn.cloudflare.net" || shop.Attributes[attrRuleVersion] != networkenrich.RuleVersion {
		t.Fatalf("aliased host: %+v", shop)
	}
	edge := dnsAddressFact(assets, "198.51.100.7")
	if edge == nil || edge.Attributes[attrIPRole] != ipRoleCDNEdge || edge.Attributes[attrCDNProvider] != "Cloudflare" {
		t.Fatalf("address behind an aliased edge, first seen untagged, lost its tag: %+v", edge)
	}
	if listed := dnsAddressFact(assets, "104.16.1.1"); listed == nil || listed.Attributes[attrIPRole] != ipRoleCDNEdge {
		t.Fatalf("listed range address: %+v", listed)
	}
	www := dnsFact(assets, "www.example.com")
	if www == nil || www.Attributes[attrDNSCNAME] != "" || www.Attributes[attrCDNStatus] != "" {
		t.Fatalf("own alias treated as edge evidence: %+v", www)
	}
	if origin := dnsAddressFact(assets, "192.0.2.5"); origin == nil || len(origin.Attributes) != 0 {
		t.Fatalf("plain address tagged: %+v", origin)
	}
	ownAlias := false
	for _, relation := range relations {
		if relation.RelationType == "cname_to" && relation.To.NaturalKey == "subdomain:origin.example.com" {
			ownAlias = true
		}
	}
	if !ownAlias {
		t.Fatal("in-scope alias no longer becomes a cname_to relation")
	}
	// Edge addresses still keep their resolution relations; ASM decides what
	// an edge means for the inventory.
	if got := resolvesTo(relations, "shop.example.com"); len(got) != 1 {
		t.Fatalf("edge resolution relation dropped: %v", got)
	}
}

func TestBoundedJoinStopsAtTheLimit(t *testing.T) {
	if got := boundedJoin([]string{"aaaa", "bbbb", "cccc"}, 9); got != "aaaa,bbbb" {
		t.Fatalf("got %q", got)
	}
}
