// Package webview defines engine-independent website observations and read views.
package webview

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Attribution struct {
	Status   string   `json:"status"`
	Provider string   `json:"provider,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}
type Observation struct {
	Outcome       string      `json:"outcome"`
	ErrorKind     string      `json:"error_kind,omitempty"`
	FinalURL      string      `json:"final_url,omitempty"`
	RedirectChain []string    `json:"redirect_chain,omitempty"`
	ResolvedIPs   []string    `json:"resolved_ips"`
	ConnectedIP   string      `json:"connected_ip,omitempty"`
	CNAMEs        []string    `json:"cname_chain"`
	CDN           Attribution `json:"cdn"`
	Cloud         Attribution `json:"cloud"`
	ObservedAt    string      `json:"observed_at,omitempty"`
	RuleVersion   string      `json:"rule_version,omitempty"`
}
type Website struct {
	EnrichmentState   string     `json:"enrichment_state"`
	EnrichmentError   string     `json:"enrichment_error,omitempty"`
	NetworkSource     string     `json:"network_source,omitempty"`
	NetworkObservedAt string     `json:"network_observed_at,omitempty"`
	NetworkStatus     string     `json:"network_status,omitempty"`
	InfoObservedAt    *time.Time `json:"info_observed_at,omitempty"`
	AssetID           uint64     `json:"asset_id"`
	RunID             uint64     `json:"run_id"`
	URL               string     `json:"url"`
	Title             string     `json:"title"`
	StatusCode        int        `json:"status_code"`
	Fingerprints      []string   `json:"fingerprints"`
	ObservedAt        time.Time  `json:"observed_at"`
	// Provider and ActiveProbe describe where the shown observation came from;
	// a passive provider means a search-engine crawl, not this platform's probe.
	Provider    string `json:"provider"`
	ActiveProbe bool   `json:"active_probe"`
	// Management fields of the linked asset; empty when the site is not an asset.
	Owner        string `json:"owner"`
	BusinessUnit string `json:"business_unit"`
	AssetStatus  string `json:"asset_status"`
	Observation
}
type Summary struct {
	Total         int64 `json:"total"`
	Responded     int64 `json:"responded"`
	Titled        int64 `json:"titled"`
	Fingerprinted int64 `json:"fingerprinted"`
}
type Page struct {
	Items      []Website `json:"items"`
	Total      int64     `json:"total"`
	PageNumber int       `json:"page_number"`
	PageSize   int       `json:"page_size"`
	Summary    Summary   `json:"summary"`
}

// Valid bounds optional engine metadata before it enters persistent evidence.
func (o *Observation) Valid() bool {
	if o == nil {
		return true
	}
	if len(o.ResolvedIPs) > 32 || len(o.CNAMEs) > 16 || len(o.RedirectChain) > 10 || len(o.FinalURL) > 2048 || len(o.ErrorKind) > 64 || len(o.RuleVersion) > 64 || len(o.ObservedAt) > 64 {
		return false
	}
	for _, ip := range append(append([]string{}, o.ResolvedIPs...), o.ConnectedIP) {
		if ip != "" {
			if _, err := netip.ParseAddr(ip); err != nil {
				return false
			}
		}
	}
	for _, name := range o.CNAMEs {
		if len(name) > 253 {
			return false
		}
	}
	for _, value := range o.RedirectChain {
		if len(value) > 2048 {
			return false
		}
	}
	for _, a := range []Attribution{o.CDN, o.Cloud} {
		if a.Status != "" && a.Status != "unknown" && a.Status != "identified" {
			return false
		}
		if len(a.Provider) > 128 || len(a.Evidence) > 16 {
			return false
		}
		for _, e := range a.Evidence {
			if len(e) > 512 {
				return false
			}
		}
	}
	switch o.Outcome {
	case "responded", "timeout", "dns_error", "network_error", "tls_error", "cancelled", "unknown":
		return true
	default:
		return false
	}
}

func decodeWebsite(raw, serviceJSON []byte) (Website, error) {
	var fact struct {
		Name        string       `json:"name"`
		Value       string       `json:"value"`
		URL         string       `json:"url"`
		Fingerprint string       `json:"fingerprint"`
		Web         *Observation `json:"web_observation"`
	}
	if err := json.Unmarshal(raw, &fact); err != nil {
		return Website{}, err
	}
	out := Website{URL: fact.URL, Title: fact.Name, EnrichmentState: "not_started", Fingerprints: []string{}, Observation: Observation{Outcome: "unknown", ResolvedIPs: []string{}, CNAMEs: []string{}, CDN: Attribution{Status: "unknown"}, Cloud: Attribution{Status: "unknown"}}}
	if fact.Name == fact.URL {
		out.Title = ""
	}
	if code, err := strconv.Atoi(fact.Value); err == nil && code >= 100 && code <= 599 {
		out.StatusCode = code
		out.Outcome = "responded"
	}
	if fact.Web != nil && fact.Web.Valid() {
		out.Observation = *fact.Web
	}
	if out.ResolvedIPs == nil {
		out.ResolvedIPs = []string{}
	}
	if out.CNAMEs == nil {
		out.CNAMEs = []string{}
	}
	if out.CDN.Status == "" {
		out.CDN.Status = "unknown"
	}
	if out.Cloud.Status == "" {
		out.Cloud.Status = "unknown"
	}
	if len(out.ResolvedIPs) > 0 || len(out.CNAMEs) > 0 || out.CDN.Status == "identified" || out.Cloud.Status == "identified" {
		out.NetworkSource = "active_engine"
		out.NetworkObservedAt = out.Observation.ObservedAt
	}
	var names []string
	_ = json.Unmarshal(serviceJSON, &names)
	if len(names) == 0 && fact.Fingerprint != "" {
		names = strings.Split(fact.Fingerprint, ",")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" && !seen[name] {
			out.Fingerprints = append(out.Fingerprints, name)
			seen[name] = true
		}
	}
	sort.Strings(out.Fingerprints)
	return out, nil
}

// applyEnrichment attaches a separate Baiyan observation to this exact website
// observation. It never changes the HTTP outcome, connected IP or historical
// page information, even when DNS enrichment failed after a successful scan.
func (w *Website) applyEnrichment(state, errorSummary string, raw []byte) {
	w.EnrichmentState = state
	w.EnrichmentError = errorSummary
	if state != "complete" || len(raw) == 0 {
		return
	}
	var network struct {
		Status string `json:"status"`
		Observation
	}
	if json.Unmarshal(raw, &network) != nil || (network.Status != "success" && network.Status != "partial") {
		return
	}
	network.Outcome = "unknown"
	if !network.Observation.Valid() {
		return
	}
	if _, err := time.Parse(time.RFC3339, network.ObservedAt); err != nil {
		return
	}
	w.NetworkSource = "baiyan"
	w.NetworkObservedAt = network.ObservedAt
	w.NetworkStatus = network.Status
	w.ResolvedIPs = append([]string{}, network.ResolvedIPs...)
	w.CNAMEs = append([]string{}, network.CNAMEs...)
	w.CDN = network.CDN
	w.Cloud = network.Cloud
	w.RuleVersion = network.RuleVersion
	if w.CDN.Status == "" {
		w.CDN.Status = "unknown"
	}
	if w.Cloud.Status == "" {
		w.Cloud.Status = "unknown"
	}
}
