package webview

import (
	"encoding/json"
	"testing"
)

func TestLegacyWebsiteUnknownAndFullFingerprints(t *testing.T) {
	item, err := decodeWebsite([]byte(`{"url":"http://example.test:80","name":"http://example.test:80","value":"unknown","fingerprint":"truncated"}`), []byte(`["nginx","React","nginx"]`))
	if err != nil {
		t.Fatal(err)
	}
	if item.Title != "" || item.Outcome != "unknown" || len(item.Fingerprints) != 2 || item.CDN.Status != "unknown" {
		t.Fatalf("unexpected legacy result: %+v", item)
	}
}
func TestHTTPErrorIsStillAResponse(t *testing.T) {
	item, err := decodeWebsite([]byte(`{"url":"https://example.test","name":"Forbidden","value":"403"}`), nil)
	if err != nil || item.StatusCode != 403 || item.Outcome != "responded" {
		t.Fatalf("HTTP response misclassified: %+v %v", item, err)
	}
}
func TestObservationRejectsMalformedIP(t *testing.T) {
	var o Observation
	if err := json.Unmarshal([]byte(`{"outcome":"responded","resolved_ips":["not an IP"]}`), &o); err != nil {
		t.Fatal(err)
	}
	if o.Valid() {
		t.Fatal("invalid IP accepted")
	}
}
func TestInvalidWebsiteFilters(t *testing.T) {
	for _, q := range []Query{{Page: 0, Size: 20}, {Page: 1, Size: 1000}, {Page: 1, Size: 20, CDN: "false"}} {
		if q.Valid() {
			t.Fatal("invalid query accepted")
		}
	}
}

func TestNetworkEnrichmentPreservesHTTPObservation(t *testing.T) {
	item, err := decodeWebsite([]byte(`{"url":"https://example.test","name":"Original title","value":"403","fingerprint":"nginx","web_observation":{"outcome":"responded","connected_ip":"192.0.2.1","final_url":"https://example.test/login","resolved_ips":["192.0.2.1"],"observed_at":"2026-09-16T01:00:00Z"}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	item.applyEnrichment("complete", "", []byte(`{"status":"partial","resolved_ips":["192.0.2.2"],"connected_ip":"192.0.2.3","final_url":"https://other.test","outcome":"dns_error","cname_chain":["edge.cloudfront.net"],"cdn":{"status":"identified","provider":"CloudFront"},"cloud":{"status":"unknown"},"observed_at":"2026-09-16T01:05:00Z","rule_version":"baiyan-network-v1"}`))
	if item.Title != "Original title" || item.StatusCode != 403 || item.Outcome != "responded" || item.ConnectedIP != "192.0.2.1" || item.FinalURL != "https://example.test/login" {
		t.Fatalf("network lookup changed HTTP evidence: %+v", item)
	}
	if item.NetworkSource != "baiyan" || item.NetworkStatus != "partial" || item.NetworkObservedAt != "2026-09-16T01:05:00Z" || item.ResolvedIPs[0] != "192.0.2.2" || item.CDN.Provider != "CloudFront" {
		t.Fatalf("separate Baiyan evidence missing: %+v", item)
	}
}

func TestFailedEnrichmentDoesNotBecomeHTTPFailure(t *testing.T) {
	item, err := decodeWebsite([]byte(`{"url":"https://example.test","name":"Title","value":"200"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	item.applyEnrichment("failed", "Baiyan unavailable", []byte(`{"status":"failed","outcome":"dns_error"}`))
	if item.EnrichmentState != "failed" || item.EnrichmentError != "Baiyan unavailable" || item.Outcome != "responded" || item.StatusCode != 200 || item.NetworkSource != "" {
		t.Fatalf("HTTP and enrichment failures conflated: %+v", item)
	}
}
