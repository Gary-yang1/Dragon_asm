package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"baiyan/internal/contract"
	"baiyan/internal/job"
)

const maxBatchFacts = 500

type PassiveProvider interface {
	Name() string
	Discover(ctx context.Context, rootDomain string) ([]string, error)
}

type DNSResult struct {
	Host   string   `json:"host"`
	IPs    []string `json:"ips"`
	CNAMEs []string `json:"cnames"`
}

type Resolver interface {
	Resolve(ctx context.Context, hosts []string, concurrency int, gate operationGate) ([]DNSResult, error)
}

type BatchSender interface {
	Send(ctx context.Context, callbackURL string, batch contract.CallbackBatch, retryLimit int) error
}

type PassiveExecutor struct {
	providers []PassiveProvider
	resolver  Resolver
	sender    BatchSender
	now       func() time.Time
	newGate   func(int) (operationGate, error)
}

func NewPassiveExecutor(providers []PassiveProvider, resolver Resolver, sender BatchSender) *PassiveExecutor {
	return &PassiveExecutor{
		providers: providers, resolver: resolver, sender: sender,
		now: func() time.Time { return time.Now().UTC() }, newGate: newOperationGate,
	}
}

func (e *PassiveExecutor) Execute(ctx context.Context, request contract.ScanRequest) (job.ExecutionResult, error) {
	if e.sender == nil {
		return job.ExecutionResult{}, errors.New("baiyan passive: callback sender is required")
	}
	gate, err := e.newGate(request.RateLimit)
	if err != nil {
		return job.ExecutionResult{}, err
	}
	if err := e.send(ctx, request, contract.CallbackBatch{
		SchemaVersion: contract.SchemaVersion, RunID: request.RunID, Seq: 1,
		Phase: "started", Status: "running", ObservedAt: e.now(),
		Assets: []contract.AssetFact{}, Relations: []contract.RelationFact{}, Exposures: []contract.ExposureFact{}, ProviderErrors: []contract.ProviderError{}, ErrorSummary: "",
	}); err != nil {
		return job.ExecutionResult{}, err
	}

	assets := make([]contract.AssetFact, 0)
	relations := make([]contract.RelationFact, 0)
	providerErrors := make([]contract.ProviderError, 0)
	hosts := make(map[string]struct{})
	hostTypes := make(map[string]string)
	rootRefs := make(map[string]string)
	maxResults := requestMaxResults(request.Options)
	requestedSources := requestedProviderSources(request.Options)
	requestedRecords := requestedDNSRecordTypes(request.JobType, request.Options)
	if request.JobType == "passive_intel" && len(e.providers) == 0 {
		providerErrors = append(providerErrors, contract.ProviderError{
			Provider: "engine", Code: "NO_PROVIDER_CONFIGURED", Message: "no passive provider is configured", Retryable: false,
		})
	} else if request.JobType == "passive_intel" {
		configured := make(map[string]bool, len(e.providers))
		for _, provider := range e.providers {
			configured[strings.ToLower(strings.TrimSpace(provider.Name()))] = true
		}
		missingSources := make([]string, 0)
		for source := range requestedSources {
			if !configured[source] {
				missingSources = append(missingSources, source)
			}
		}
		sort.Strings(missingSources)
		for _, source := range missingSources {
			providerErrors = append(providerErrors, contract.ProviderError{
				Provider: source, Code: "PROVIDER_NOT_CONFIGURED", Message: "requested provider is not configured", Retryable: false,
			})
		}
	}
	for _, target := range request.Targets {
		root := normalizeDomain(target.Value)
		rootRef := stableRef("root", root)
		rootRefs[root] = rootRef
		assetType := "domain"
		if target.Type == "subdomain" {
			assetType = "subdomain"
		}
		assets = append(assets, assetFact(rootRef, assetType+":"+root, assetType, root, "scope", e.now()))
		if request.JobType == "dns" {
			hosts[root] = struct{}{}
			hostTypes[root] = assetType
			continue
		}
		for _, provider := range e.providers {
			if len(requestedSources) > 0 && !requestedSources[provider.Name()] {
				continue
			}
			if err := gate.Wait(ctx); err != nil {
				return job.ExecutionResult{}, err
			}
			providerCtx, cancel := context.WithTimeout(ctx, providerTimeout(request.TimeoutSeconds))
			found, err := provider.Discover(providerCtx, root)
			cancel()
			if err != nil {
				providerErrors = append(providerErrors, contract.ProviderError{
					Provider: provider.Name(), Code: "PROVIDER_UNAVAILABLE", Message: "provider request failed", Retryable: true,
				})
				continue
			}
			if len(found) > 1000 {
				found = found[:1000]
			}
			seen := make(map[string]struct{})
			for _, candidate := range found {
				if len(hosts) >= maxResults {
					break
				}
				host := normalizeDomain(candidate)
				if host == "" || host == root || !withinRoot(host, root) {
					continue
				}
				if _, duplicate := seen[host]; duplicate {
					continue
				}
				seen[host] = struct{}{}
				hosts[host] = struct{}{}
				hostTypes[host] = "subdomain"
				ref := stableRef(provider.Name(), host)
				assets = append(assets, assetFact(ref, "subdomain:"+host, "subdomain", host, provider.Name(), e.now()))
				relations = append(relations, relationFact(
					stableRef("contains", provider.Name(), root, host), "contains",
					rootRef, "domain:"+root, ref, "subdomain:"+host, provider.Name(), e.now(),
				))
			}
		}
	}

	if e.resolver != nil && len(hosts) > 0 {
		hostList := make([]string, 0, len(hosts))
		for host := range hosts {
			hostList = append(hostList, host)
		}
		sort.Strings(hostList)
		resolved, err := e.resolver.Resolve(ctx, hostList, request.Concurrency, gate)
		if err != nil {
			providerErrors = append(providerErrors, contract.ProviderError{
				Provider: "dns", Code: "DNS_PARTIAL_FAILURE", Message: "DNS resolution was incomplete", Retryable: true,
			})
		}
		for _, result := range resolved {
			host := normalizeDomain(result.Host)
			if _, authorized := hosts[host]; !authorized {
				continue
			}
			fromRef := stableRef("dns-parent", host)
			// Provider-specific subdomain refs differ; add a DNS observation so
			// DNS relations always resolve within the same callback batch.
			hostType := hostTypes[host]
			if hostType == "" {
				hostType = "subdomain"
			}
			assets = append(assets, assetFact(fromRef, hostType+":"+host, hostType, host, "dns", e.now()))
			for _, rawIP := range result.IPs {
				ip := net.ParseIP(strings.TrimSpace(rawIP))
				if ip == nil {
					continue
				}
				if (ip.To4() != nil && !requestedRecords["A"]) || (ip.To4() == nil && !requestedRecords["AAAA"]) {
					continue
				}
				canonical := ip.String()
				ipRef := stableRef("ip", canonical)
				assets = append(assets, assetFact(ipRef, "ip:"+canonical, "ip", canonical, "dns", e.now()))
				relations = append(relations, relationFact(
					stableRef("resolve", host, canonical), "resolves_to",
					fromRef, hostType+":"+host, ipRef, "ip:"+canonical, "dns", e.now(),
				))
			}
			if !requestedRecords["CNAME"] {
				continue
			}
			for _, rawCNAME := range result.CNAMEs {
				cname := normalizeDomain(rawCNAME)
				root := matchingRoot(cname, rootRefs)
				if root == "" || !withinRoot(cname, root) {
					continue
				}
				cnameRef := stableRef("cname", cname)
				assets = append(assets, assetFact(cnameRef, "subdomain:"+cname, "subdomain", cname, "dns", e.now()))
				relations = append(relations, relationFact(
					stableRef("cname-rel", host, cname), "cname_to",
					fromRef, hostType+":"+host, cnameRef, "subdomain:"+cname, "dns", e.now(),
				))
			}
		}
	}

	assets = dedupeAssets(assets)
	relations = dedupeRelations(relations)
	seq := uint64(2)
	total := uint64(0)
	for len(assets) > 0 || len(relations) > 0 {
		batch := contract.CallbackBatch{
			SchemaVersion: contract.SchemaVersion, RunID: request.RunID, Seq: seq,
			Phase: "progress", Status: "running", ObservedAt: e.now(),
			Assets: []contract.AssetFact{}, Relations: []contract.RelationFact{}, Exposures: []contract.ExposureFact{}, ProviderErrors: []contract.ProviderError{}, ErrorSummary: "",
		}
		remaining := maxBatchFacts
		if take := min(remaining, len(assets)); take > 0 {
			batch.Assets, assets = assets[:take], assets[take:]
			remaining -= take
		}
		if take := min(remaining, len(relations)); take > 0 {
			batch.Relations, relations = relations[:take], relations[take:]
		}
		batch.ResultCount = uint64(batch.FactCount())
		total += batch.ResultCount
		if err := e.send(ctx, request, batch); err != nil {
			return job.ExecutionResult{ResultCount: total}, err
		}
		seq++
	}
	status := job.StatusSuccess
	if len(providerErrors) > 0 {
		status = job.StatusPartialSuccess
	}
	final := contract.CallbackBatch{
		SchemaVersion: contract.SchemaVersion, RunID: request.RunID, Seq: seq,
		Phase: "completed", Status: status, ResultCount: 0, ObservedAt: e.now(),
		Assets: []contract.AssetFact{}, Relations: []contract.RelationFact{}, Exposures: []contract.ExposureFact{}, ProviderErrors: providerErrors, ErrorSummary: "",
	}
	if err := e.send(ctx, request, final); err != nil {
		return job.ExecutionResult{ResultCount: total}, err
	}
	return job.ExecutionResult{Status: status, ResultCount: total}, nil
}

func (e *PassiveExecutor) send(ctx context.Context, request contract.ScanRequest, batch contract.CallbackBatch) error {
	return e.sender.Send(ctx, request.CallbackURL, batch, 3)
}

func assetFact(ref, naturalKey, assetType, value, provider string, observed time.Time) contract.AssetFact {
	return contract.AssetFact{
		FactMeta: contract.FactMeta{
			ClientRef: ref, NaturalKey: naturalKey, Source: "baiyan", Provider: provider,
			ObservedAt: observed, Confidence: 90, ActiveProbe: false,
			EvidenceHash: evidenceHash(provider, assetType, value), EvidenceRef: provider + ":" + value,
		},
		AssetType: assetType, Value: value,
	}
}

func relationFact(ref, relationType, fromRef, fromNatural, toRef, toNatural, provider string, observed time.Time) contract.RelationFact {
	return contract.RelationFact{
		FactMeta: contract.FactMeta{
			ClientRef: ref, NaturalKey: "relation:" + relationType + ":" + fromRef + ":" + toRef,
			Source: "baiyan", Provider: provider, ObservedAt: observed, Confidence: 90,
			ActiveProbe: false, EvidenceHash: evidenceHash(provider, relationType, fromRef, toRef),
		},
		RelationType: relationType,
		From:         contract.FactReference{ClientRef: fromRef, NaturalKey: fromNatural},
		To:           contract.FactReference{ClientRef: toRef, NaturalKey: toNatural},
	}
}

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return ""
			}
		}
	}
	return value
}

func withinRoot(host, root string) bool { return host == root || strings.HasSuffix(host, "."+root) }

func matchingRoot(host string, roots map[string]string) string {
	best := ""
	for root := range roots {
		if withinRoot(host, root) && len(root) > len(best) {
			best = root
		}
	}
	return best
}

func stableRef(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return parts[0] + "-" + hex.EncodeToString(sum[:8])
}

func evidenceHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func providerTimeout(jobTimeout int) time.Duration {
	if jobTimeout <= 0 || jobTimeout > 30 {
		return 30 * time.Second
	}
	return time.Duration(jobTimeout) * time.Second
}

func requestMaxResults(options map[string]any) int {
	value := options["max_results"]
	switch typed := value.(type) {
	case float64:
		if typed >= 1 && typed <= 10000 {
			return int(typed)
		}
	case int:
		if typed >= 1 && typed <= 10000 {
			return typed
		}
	}
	return 500
}

func requestedProviderSources(options map[string]any) map[string]bool {
	result := make(map[string]bool)
	switch values := options["sources"].(type) {
	case []any:
		for _, value := range values {
			if text, ok := value.(string); ok {
				result[strings.ToLower(strings.TrimSpace(text))] = true
			}
		}
	case []string:
		for _, value := range values {
			result[strings.ToLower(strings.TrimSpace(value))] = true
		}
	}
	return result
}

func requestedDNSRecordTypes(jobType string, options map[string]any) map[string]bool {
	if jobType != "dns" {
		return map[string]bool{"A": true, "AAAA": true, "CNAME": true}
	}
	result := make(map[string]bool)
	switch values := options["record_types"].(type) {
	case []any:
		for _, value := range values {
			if text, ok := value.(string); ok {
				result[strings.TrimSpace(text)] = true
			}
		}
	case []string:
		for _, value := range values {
			result[strings.TrimSpace(value)] = true
		}
	}
	return result
}

func dedupeAssets(items []contract.AssetFact) []contract.AssetFact {
	seen := make(map[string]struct{})
	out := make([]contract.AssetFact, 0, len(items))
	for _, item := range items {
		key := item.Provider + "|" + item.AssetType + "|" + item.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func dedupeRelations(items []contract.RelationFact) []contract.RelationFact {
	seen := make(map[string]struct{})
	out := make([]contract.RelationFact, 0, len(items))
	for _, item := range items {
		key := item.Provider + "|" + item.RelationType + "|" + item.From.ClientRef + "|" + item.To.ClientRef
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
