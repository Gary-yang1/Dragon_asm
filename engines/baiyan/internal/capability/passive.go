package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
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
	Host      string   `json:"host"`
	Status    string   `json:"status,omitempty"`
	ErrorCode string   `json:"error_code,omitempty"`
	IPs       []string `json:"ips"`
	CNAMEs    []string `json:"cnames"`
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
	// randomLabel names wildcard probes; replaceable so tests are deterministic.
	randomLabel func() string
}

func NewPassiveExecutor(providers []PassiveProvider, resolver Resolver, sender BatchSender) *PassiveExecutor {
	return &PassiveExecutor{
		providers: providers, resolver: resolver, sender: sender,
		now: func() time.Time { return time.Now().UTC() }, newGate: newOperationGate,
		randomLabel: randomDNSLabel,
	}
}

// StreamingPassiveProvider may publish discoveries before its source finishes.
type StreamingPassiveProvider interface {
	DiscoverStream(context.Context, string, func([]string) error) error
}

type streamResumer interface {
	ResumeStream(context.Context, contract.ScanRequest) (uint64, uint64, *job.ExecutionResult, error)
}

func (e *PassiveExecutor) Execute(ctx context.Context, request contract.ScanRequest) (job.ExecutionResult, error) {
	if e.sender == nil {
		return job.ExecutionResult{}, errors.New("baiyan passive: callback sender is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	gate, err := e.newGate(request.RateLimit)
	if err != nil {
		return job.ExecutionResult{}, err
	}
	seq, total := uint64(1), uint64(0)
	if sender, ok := e.sender.(streamResumer); ok {
		var done *job.ExecutionResult
		seq, total, done, err = sender.ResumeStream(ctx, request)
		if err != nil {
			return job.ExecutionResult{}, err
		}
		if done != nil {
			return *done, nil
		}
	}
	result := func(err error) (job.ExecutionResult, error) { return job.ExecutionResult{ResultCount: total}, err }
	var sendWith func(string, string, []contract.AssetFact, []contract.RelationFact, []contract.ExposureFact, *contract.StageProgress, []contract.ProviderError, string) error
	send := func(phase, status string, assets []contract.AssetFact, relations []contract.RelationFact, progress *contract.StageProgress, errs []contract.ProviderError, summary string) error {
		return sendWith(phase, status, assets, relations, nil, progress, errs, summary)
	}
	sendWith = func(phase, status string, assets []contract.AssetFact, relations []contract.RelationFact, exposures []contract.ExposureFact, progress *contract.StageProgress, errs []contract.ProviderError, summary string) error {
		if exposures == nil {
			exposures = []contract.ExposureFact{}
		}
		if assets == nil {
			assets = []contract.AssetFact{}
		}
		if relations == nil {
			relations = []contract.RelationFact{}
		}
		if errs == nil {
			errs = []contract.ProviderError{}
		}
		batch := contract.CallbackBatch{SchemaVersion: contract.SchemaVersion, RunID: request.RunID, Seq: seq, Phase: phase, Status: status, ObservedAt: e.now(), Assets: assets, Relations: relations, Exposures: exposures, ProviderErrors: errs, ErrorSummary: summary, StageProgress: progress}
		if progress != nil {
			snapshot := *progress
			batch.StageProgress = &snapshot
		}
		batch.ResultCount = uint64(batch.FactCount())
		if err := e.send(ctx, request, batch); err != nil {
			return err
		}
		seq++
		total += batch.ResultCount
		return nil
	}
	if err := send("started", "running", nil, nil, nil, nil, ""); err != nil {
		return result(err)
	}
	hosts := map[string]string{}
	roots := map[string]string{}
	maxResults := requestMaxResults(request.Options)
	requested := requestedProviderSources(request.Options)
	records := requestedDNSRecordTypes(request.JobType, request.Options)
	if requested["auto"] {
		requested = map[string]bool{}
		for _, provider := range e.providers {
			requested[provider.Name()] = true
		}
	}
	providerErrors := []contract.ProviderError{}
	configured := map[string]bool{}
	for _, p := range e.providers {
		configured[p.Name()] = true
	}
	if request.JobType == "passive_intel" {
		if len(e.providers) == 0 && len(requested) == 0 {
			requested["engine"] = true
		}
		for source := range requested {
			if !configured[source] {
				pe := contract.ProviderError{Provider: source, Code: "PROVIDER_NOT_CONFIGURED", Message: "requested provider is not configured", Retryable: false}
				providerErrors = append(providerErrors, pe)
				if err := send("progress", "running", nil, nil, &contract.StageProgress{Stage: "collect", Provider: source, Status: "skipped", Message: pe.Message}, []contract.ProviderError{pe}, ""); err != nil {
					return result(err)
				}
			}
		}
	}
	for _, target := range request.Targets {
		root := normalizeDomain(target.Value)
		if root == "" {
			continue
		}
		rootRef := stableRef("root", root)
		roots[root] = rootRef
		kind := "domain"
		if target.Type == "subdomain" {
			kind = "subdomain"
		}
		if err := send("progress", "running", []contract.AssetFact{assetFact(rootRef, kind+":"+root, kind, root, "scope", e.now())}, nil, nil, nil, ""); err != nil {
			return result(err)
		}
		if request.JobType == "dns" {
			hosts[root] = kind
			continue
		}
		type event struct {
			provider string
			found    []string
			sites    []SiteSnapshot
			err      error
			done     bool
			started  bool
		}
		events := make(chan event, 16)
		var wg sync.WaitGroup
		workers := min(4, request.Concurrency)
		if workers < 1 {
			workers = 1
		}
		slots := make(chan struct{}, workers)
		publish := func(ev event) error {
			select {
			case events <- ev:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		for _, provider := range e.providers {
			if len(requested) > 0 && !requested[provider.Name()] {
				continue
			}
			provider := provider
			if scoped, ok := provider.(interface{ WithRateLimit(int) PassiveProvider }); ok {
				rate := request.RateLimit / workers
				if rate < 1 {
					rate = 1
				}
				provider = scoped.WithRateLimit(rate)
			}
			if scoped, ok := provider.(interface {
				WithGate(operationGate) PassiveProvider
			}); ok {
				provider = scoped.WithGate(gate)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case slots <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-slots }()
				if err := publish(event{provider: provider.Name(), started: true}); err != nil {
					return
				}
				err := gate.Wait(ctx)
				if err == nil {
					duration := providerTimeout(request.TimeoutSeconds)
					if provider.Name() == "subfinder" {
						duration = 5 * time.Minute
					}
					child, stop := context.WithTimeout(ctx, duration)
					if stream, ok := provider.(StreamingPassiveProvider); ok {
						err = stream.DiscoverStream(child, root, func(items []string) error { return publish(event{provider: provider.Name(), found: items}) })
					} else {
						var found []string
						var sites []SiteSnapshot
						if crawler, ok := provider.(SiteSnapshotProvider); ok {
							found, sites, err = crawler.DiscoverSites(child, root)
						} else {
							found, err = provider.Discover(child, root)
						}
						if len(found) > 0 || len(sites) > 0 {
							if sendErr := publish(event{provider: provider.Name(), found: found, sites: sites}); sendErr != nil {
								err = sendErr
							}
						}
					}
					stop()
				}
				_ = publish(event{provider: provider.Name(), err: err, done: true})
			}()
		}
		go func() { wg.Wait(); close(events) }()
		seen := map[string]map[string]bool{}
		counts := map[string]int{}
		running := map[string]bool{}
		ticker := time.NewTicker(5 * time.Second)
		loop := true
		for loop {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return result(ctx.Err())
			case <-ticker.C:
				// A heartbeat keeps slow providers visibly alive without inventing percentages.
				for source := range running {
					if err := send("progress", "running", nil, nil, &contract.StageProgress{Stage: "collect", Provider: source, Target: root, Status: "running", Discovered: counts[source]}, nil, ""); err != nil {
						ticker.Stop()
						return result(err)
					}
				}
			case ev, ok := <-events:
				if !ok {
					loop = false
					continue
				}
				if ev.started {
					running[ev.provider] = true
				}
				if seen[ev.provider] == nil {
					seen[ev.provider] = map[string]bool{}
				}
				assets := []contract.AssetFact{}
				relations := []contract.RelationFact{}
				flush := func() error {
					if len(assets) == 0 {
						return nil
					}
					err := send("progress", "running", assets, relations, &contract.StageProgress{Stage: "collect", Provider: ev.provider, Target: root, Status: "running", Discovered: counts[ev.provider]}, nil, "")
					assets = nil
					relations = nil
					return err
				}
				for _, raw := range ev.found {
					host := normalizeDomain(raw)
					if host == "" || host == root || !withinRoot(host, root) || seen[ev.provider][host] {
						continue
					}
					if _, exists := hosts[host]; !exists && len(hosts) >= maxResults {
						continue
					}
					seen[ev.provider][host] = true
					hosts[host] = "subdomain"
					counts[ev.provider]++
					ref := stableRef(ev.provider, host)
					assets = append(assets, assetFact(ref, "subdomain:"+host, "subdomain", host, ev.provider, e.now()))
					relations = append(relations, relationFact(stableRef("contains", ev.provider, root, host), "contains", rootRef, "domain:"+root, ref, "subdomain:"+host, ev.provider, e.now()))
					if len(assets) >= 100 {
						if err := flush(); err != nil {
							ticker.Stop()
							return result(err)
						}
					}
				}
				if err := flush(); err != nil {
					ticker.Stop()
					return result(err)
				}
				if len(ev.sites) > 0 {
					// Only sites on hosts this job accepted become facts, so a crawl
					// can never introduce a host the scope and result cap rejected.
					siteAssets, siteRelations, siteExposures := siteFacts(ev.provider, ev.sites, func(host string) (string, string, bool) {
						if host == root {
							return kind + ":" + root, rootRef, true
						}
						if hosts[host] == "subdomain" && withinRoot(host, root) {
							return "subdomain:" + host, stableRef(ev.provider, host), true
						}
						return "", "", false
					}, e.now())
					// Each site is three facts; 150 keeps a batch under maxBatchFacts.
					for start := 0; start < len(siteAssets); start += 150 {
						end := min(start+150, len(siteAssets))
						if err := sendWith("progress", "running", siteAssets[start:end], siteRelations[start:end], siteExposures[start:end], nil, nil, ""); err != nil {
							ticker.Stop()
							return result(err)
						}
					}
				}
				if ev.started || ev.done {
					status, message := "running", ""
					errs := []contract.ProviderError{}
					if ev.done {
						delete(running, ev.provider)
						status = "success"
						if ev.err != nil {
							status = "failed"
							if counts[ev.provider] > 0 {
								status = "partial"
							}
							message = "provider request failed; available discoveries were retained"
							pe := contract.ProviderError{Provider: ev.provider, Code: "PROVIDER_UNAVAILABLE", Message: message, Retryable: true}
							providerErrors = append(providerErrors, pe)
							errs = append(errs, pe)
						}
					}
					if err := send("progress", "running", nil, nil, &contract.StageProgress{Stage: "collect", Provider: ev.provider, Target: root, Status: status, Discovered: counts[ev.provider], Message: message}, errs, ""); err != nil {
						ticker.Stop()
						return result(err)
					}
				}
			}
		}
		ticker.Stop()
	}
	if e.resolver != nil && len(hosts) > 0 {
		list := make([]string, 0, len(hosts))
		for host := range hosts {
			list = append(list, host)
		}
		sort.Strings(list)
		failed, noRecords := 0, 0
		batchSize := min(25, request.Concurrency*2)
		if batchSize < 1 {
			batchSize = 1
		}
		if limited, ok := e.resolver.(interface{ BatchSize() int }); ok {
			batchSize = min(batchSize, limited.BatchSize())
			if batchSize < 1 {
				batchSize = 1
			}
		}
		// Hosts whose only answer is their zone's wildcard are almost always
		// names a source remembered rather than records that exist. They keep
		// their asset (a source did report them) but get no address relations,
		// which would otherwise attach hundreds of phantom names to one IP.
		wildcards := e.detectWildcards(ctx, list, roots, request.Concurrency, batchSize, gate)
		if ctx.Err() != nil {
			return result(ctx.Err())
		}
		for start := 0; start < len(list); start += batchSize {
			end := min(start+batchSize, len(list))
			progress := &contract.StageProgress{Stage: "dns", Provider: "dns", Status: "running", Completed: start, Total: len(list), Failed: failed, NoRecords: noRecords}
			if err := send("progress", "running", nil, nil, progress, nil, ""); err != nil {
				return result(err)
			}
			resolved, resolveErr := e.resolver.Resolve(ctx, list[start:end], request.Concurrency, gate)
			if ctx.Err() != nil {
				return result(ctx.Err())
			}
			assets := []contract.AssetFact{}
			relations := []contract.RelationFact{}
			chunkSet := map[string]bool{}
			for _, host := range list[start:end] {
				chunkSet[host] = true
			}
			detailedFailure := false
			for _, entry := range resolved {
				host := normalizeDomain(entry.Host)
				if !chunkSet[host] {
					continue
				}
				if entry.Status == "failed" {
					failed++
					detailedFailure = true
				}
				if entry.Status == "no_records" {
					noRecords++
				}
				kind := hosts[host]
				ref := stableRef("dns-parent", host)
				fact := assetFact(ref, kind+":"+host, kind, host, "dns", e.now())
				fact.Attributes = map[string]string{"dns_status": entry.Status, "dns_error": entry.ErrorCode}
				if answer, ok := wildcards[parentZone(host)]; ok && entry.Status == "success" && answer.matchesWildcard(entry) {
					fact.Attributes["dns_wildcard"] = "suspected"
					assets = append(assets, fact)
					continue
				}
				assets = append(assets, fact)
				for _, raw := range entry.IPs {
					ip := net.ParseIP(strings.TrimSpace(raw))
					if ip == nil || ip.To4() != nil && !records["A"] || ip.To4() == nil && !records["AAAA"] {
						continue
					}
					value := ip.String()
					to := stableRef("ip", value)
					assets = append(assets, assetFact(to, "ip:"+value, "ip", value, "dns", e.now()))
					relations = append(relations, relationFact(stableRef("resolve", host, value), "resolves_to", ref, kind+":"+host, to, "ip:"+value, "dns", e.now()))
				}
				if records["CNAME"] {
					for _, raw := range entry.CNAMEs {
						value := normalizeDomain(raw)
						if value == "" || matchingRoot(value, roots) == "" {
							continue
						}
						to := stableRef("cname", value)
						assets = append(assets, assetFact(to, "subdomain:"+value, "subdomain", value, "dns", e.now()))
						relations = append(relations, relationFact(stableRef("cname-rel", host, value), "cname_to", ref, kind+":"+host, to, "subdomain:"+value, "dns", e.now()))
					}
				}
			}
			if resolveErr != nil && !detailedFailure {
				failed++
			}
			assets = dedupeAssets(assets)
			relations = dedupeRelations(relations)
			for len(assets) > 0 || len(relations) > 0 {
				ac := min(len(assets), maxBatchFacts)
				rc := min(len(relations), maxBatchFacts-ac)
				if err := send("progress", "running", assets[:ac], relations[:rc], nil, nil, ""); err != nil {
					return result(err)
				}
				assets = assets[ac:]
				relations = relations[rc:]
			}
			progress.Completed = end
			progress.Failed = failed
			progress.NoRecords = noRecords
			if end == len(list) {
				progress.Status = "success"
				if failed > 0 {
					progress.Status = "partial"
				}
			}
			if err := send("progress", "running", nil, nil, progress, nil, ""); err != nil {
				return result(err)
			}
		}
		if failed > 0 {
			providerErrors = append(providerErrors, contract.ProviderError{Provider: "dns", Code: "DNS_PARTIAL_FAILURE", Message: "DNS resolution was incomplete; available records were retained", Retryable: true})
		}
	}
	status, summary := "success", ""
	if len(providerErrors) > 0 {
		status = "partial_success"
		parts := []string{}
		for _, pe := range providerErrors {
			parts = append(parts, pe.Provider+": "+pe.Code)
		}
		summary = strings.Join(parts, "; ")
		if len(summary) > 1000 {
			summary = summary[:1000]
		}
	}
	// Bound diagnostics independently of the number of configured roots.
	if len(providerErrors) > 100 {
		providerErrors = providerErrors[:100]
	}
	if err := send("completed", status, nil, nil, nil, providerErrors, summary); err != nil {
		return result(err)
	}
	return job.ExecutionResult{Status: status, ResultCount: total, ErrorSummary: summary}, nil
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
