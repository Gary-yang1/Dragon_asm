package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"baiyan/internal/contract"
)

// zoneResolver answers from a fixed table; probe names are "probeN.<zone>" and
// resolve to the zone's wildcard answer when one is configured.
type zoneResolver struct {
	records   map[string]DNSResult
	wildcards map[string]DNSResult
	// oneProbe lists zones where only the first probe resolves.
	oneProbe map[string]bool
	failAll  bool
	seen     map[string]int
}

func (r *zoneResolver) Resolve(_ context.Context, hosts []string, _ int, _ operationGate) ([]DNSResult, error) {
	if r.failAll {
		return nil, errors.New("resolver down")
	}
	out := make([]DNSResult, 0, len(hosts))
	for _, host := range hosts {
		if strings.HasPrefix(host, "probe") {
			zone := parentZone(host)
			r.seen[zone]++
			if answer, ok := r.wildcards[zone]; ok && (!r.oneProbe[zone] || r.seen[zone] == 1) {
				answer.Host = host
				out = append(out, answer)
				continue
			}
			out = append(out, DNSResult{Host: host, Status: "no_records"})
			continue
		}
		if record, ok := r.records[host]; ok {
			record.Host = host
			out = append(out, record)
			continue
		}
		out = append(out, DNSResult{Host: host, Status: "no_records"})
	}
	return out, nil
}

func ips(values ...string) DNSResult { return DNSResult{Status: "success", IPs: values} }

func runWildcardJob(t *testing.T, resolver *zoneResolver, found []string) ([]contract.AssetFact, []contract.RelationFact, string) {
	t.Helper()
	if resolver.seen == nil {
		resolver.seen = map[string]int{}
	}
	sender := &fakeSender{}
	executor := NewPassiveExecutor([]PassiveProvider{&fakeProvider{name: "fofa", results: found}}, resolver, sender)
	probe := 0
	executor.randomLabel = func() string { probe++; return fmt.Sprintf("probe%d", probe) }
	result, err := executor.Execute(context.Background(), passiveRequest())
	if err != nil {
		t.Fatal(err)
	}
	var assets []contract.AssetFact
	var relations []contract.RelationFact
	for _, batch := range sender.batches {
		assets = append(assets, batch.Assets...)
		relations = append(relations, batch.Relations...)
	}
	return assets, relations, result.Status
}

func dnsFact(assets []contract.AssetFact, host string) *contract.AssetFact {
	for i := range assets {
		if assets[i].Provider == "dns" && assets[i].Value == host {
			return &assets[i]
		}
	}
	return nil
}

func resolvesTo(relations []contract.RelationFact, host string) []string {
	var out []string
	for _, relation := range relations {
		if relation.RelationType == "resolves_to" && strings.HasSuffix(relation.From.NaturalKey, ":"+host) {
			out = append(out, strings.TrimPrefix(relation.To.NaturalKey, "ip:"))
		}
	}
	return out
}

func TestWildcardAnswersDoNotBecomeAddressRelations(t *testing.T) {
	resolver := &zoneResolver{
		wildcards: map[string]DNSResult{"portal.example.com": ips("192.0.2.1", "192.0.2.2")},
		records: map[string]DNSResult{
			"ghost.portal.example.com": ips("192.0.2.1"),
			"real.portal.example.com":  ips("198.51.100.7"),
			"mixed.portal.example.com": ips("192.0.2.1", "198.51.100.8"),
			"api.example.com":          ips("192.0.2.1"), // same IP, but example.com has no wildcard
		},
	}
	assets, relations, status := runWildcardJob(t, resolver, []string{"ghost.portal.example.com", "real.portal.example.com", "mixed.portal.example.com", "api.example.com"})
	if status != "success" {
		t.Fatalf("status = %s", status)
	}

	ghost := dnsFact(assets, "ghost.portal.example.com")
	if ghost == nil || ghost.Attributes["dns_wildcard"] != "suspected" {
		t.Fatalf("wildcard host not flagged: %+v", ghost)
	}
	if got := resolvesTo(relations, "ghost.portal.example.com"); len(got) != 0 {
		t.Fatalf("wildcard host still linked to %v", got)
	}
	for host, want := range map[string]int{"real.portal.example.com": 1, "mixed.portal.example.com": 2, "api.example.com": 1} {
		if fact := dnsFact(assets, host); fact == nil || fact.Attributes["dns_wildcard"] != "" {
			t.Fatalf("%s wrongly flagged: %+v", host, fact)
		}
		if got := resolvesTo(relations, host); len(got) != want {
			t.Fatalf("%s relations = %v, want %d", host, got, want)
		}
	}
	// Probe names are never reported as discoveries.
	for _, fact := range assets {
		if strings.HasPrefix(fact.Value, "probe") {
			t.Fatalf("probe leaked as an asset: %+v", fact)
		}
	}
}

func TestWildcardNeedsEveryProbeToResolve(t *testing.T) {
	resolver := &zoneResolver{
		wildcards: map[string]DNSResult{"portal.example.com": ips("192.0.2.1")},
		oneProbe:  map[string]bool{"portal.example.com": true},
		records:   map[string]DNSResult{"host.portal.example.com": ips("192.0.2.1")},
	}
	assets, relations, _ := runWildcardJob(t, resolver, []string{"host.portal.example.com"})
	if fact := dnsFact(assets, "host.portal.example.com"); fact == nil || fact.Attributes["dns_wildcard"] != "" {
		t.Fatalf("one stray probe answer treated as a wildcard: %+v", fact)
	}
	if len(resolvesTo(relations, "host.portal.example.com")) != 1 {
		t.Fatal("relation dropped without a confirmed wildcard")
	}
}

func TestCNAMEWildcardIsRecognised(t *testing.T) {
	resolver := &zoneResolver{
		wildcards: map[string]DNSResult{"example.com": {Status: "success", CNAMEs: []string{"edge.example.com"}}},
		records: map[string]DNSResult{
			"ghost.example.com": {Status: "success", CNAMEs: []string{"edge.example.com"}},
			"own.example.com":   {Status: "success", CNAMEs: []string{"own-origin.example.com"}},
		},
	}
	assets, _, _ := runWildcardJob(t, resolver, []string{"ghost.example.com", "own.example.com"})
	if fact := dnsFact(assets, "ghost.example.com"); fact == nil || fact.Attributes["dns_wildcard"] != "suspected" {
		t.Fatalf("CNAME wildcard not flagged: %+v", fact)
	}
	if fact := dnsFact(assets, "own.example.com"); fact == nil || fact.Attributes["dns_wildcard"] != "" {
		t.Fatalf("distinct alias wrongly flagged: %+v", fact)
	}
}

func TestWildcardProbingFailureLeavesResolutionUnfiltered(t *testing.T) {
	executor := NewPassiveExecutor(nil, &zoneResolver{failAll: true}, &fakeSender{})
	if answers := executor.detectWildcards(context.Background(), []string{"a.portal.example.com"}, map[string]string{"example.com": "root"}, 2, 25, noopGate{}); len(answers) != 0 {
		t.Fatalf("failed probes produced wildcard answers: %v", answers)
	}
}

func TestParentZone(t *testing.T) {
	for host, want := range map[string]string{"a.b.example.com": "b.example.com", "example.com": "com", "localhost": ""} {
		if got := parentZone(host); got != want {
			t.Fatalf("parentZone(%q) = %q, want %q", host, got, want)
		}
	}
}

type noopGate struct{}

func (noopGate) Wait(context.Context) error { return nil }
