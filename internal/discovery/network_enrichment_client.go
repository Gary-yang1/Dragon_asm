package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/webview"
)

var errNetworkEnrichment = errors.New("Baiyan 网络信息补充失败")

type networkEnrichmentInput struct {
	Key          string   `json:"key"`
	Host         string   `json:"host"`
	ObservedIPs  []string `json:"observed_ips,omitempty"`
	Fingerprints []string `json:"fingerprints,omitempty"`
}
type networkEnrichmentResult struct {
	Key         string              `json:"key"`
	Host        string              `json:"host"`
	Status      string              `json:"status"`
	ResolvedIPs []string            `json:"resolved_ips"`
	CNAMEs      []string            `json:"cname_chain"`
	CDN         webview.Attribution `json:"cdn"`
	Cloud       webview.Attribution `json:"cloud"`
	ObservedAt  time.Time           `json:"observed_at"`
	RuleVersion string              `json:"rule_version"`
	ErrorKind   string              `json:"error_kind,omitempty"`
}

// enrichNetwork uses the run's immutable Baiyan adapter, never active-engine state.
func (a *HTTPEngineAdapter) enrichNetwork(ctx context.Context, items []networkEnrichmentInput) (map[string]networkEnrichmentResult, error) {
	if len(items) == 0 || len(items) > 20 {
		return nil, errNetworkEnrichment
	}
	body, _ := json.Marshal(struct {
		Version string                   `json:"schema_version"`
		Items   []networkEnrichmentInput `json:"items"`
	}{"1.0", items})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/enrich/network", bytes.NewReader(body))
	if err != nil {
		return nil, errNetworkEnrichment
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	client := a.client
	if configured, ok := client.(*http.Client); ok {
		copy := *configured
		if copy.Timeout > 0 && copy.Timeout < 20*time.Second {
			copy.Timeout = 20 * time.Second
		}
		client = &copy
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errNetworkEnrichment
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &engineStatusError{sentinel: errNetworkEnrichment, status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
	if err != nil || len(raw) > 256*1024 {
		return nil, errNetworkEnrichment
	}
	var result struct {
		Version string                    `json:"schema_version"`
		Items   []networkEnrichmentResult `json:"items"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.Version != "1.0" || len(result.Items) != len(items) {
		return nil, errNetworkEnrichment
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return nil, errNetworkEnrichment
	}
	expected := map[string]string{}
	for _, item := range items {
		if _, ok := expected[item.Key]; ok {
			return nil, errNetworkEnrichment
		}
		expected[item.Key] = item.Host
	}
	out := map[string]networkEnrichmentResult{}
	for _, item := range result.Items {
		host, ok := expected[item.Key]
		if !ok || item.Host != host || item.ObservedAt.IsZero() || item.ObservedAt.After(time.Now().Add(5*time.Minute)) || len(item.RuleVersion) > 64 || len(item.ErrorKind) > 64 {
			return nil, errNetworkEnrichment
		}
		if _, exists := out[item.Key]; exists {
			return nil, errNetworkEnrichment
		}
		if item.Status != "success" && item.Status != "partial" && item.Status != "failed" {
			return nil, errNetworkEnrichment
		}
		observation := webview.Observation{Outcome: "unknown", ResolvedIPs: item.ResolvedIPs, CNAMEs: item.CNAMEs, CDN: item.CDN, Cloud: item.Cloud}
		if !observation.Valid() {
			return nil, errNetworkEnrichment
		}
		for _, ip := range item.ResolvedIPs {
			if _, err := netip.ParseAddr(ip); err != nil {
				return nil, errNetworkEnrichment
			}
		}
		for _, name := range item.CNAMEs {
			if strings.ContainsAny(name, "\x00\r\n /:@") {
				return nil, errNetworkEnrichment
			}
		}
		out[item.Key] = item
	}
	return out, nil
}
