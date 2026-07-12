package baiyan

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var domainTokenRegexp = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_-])(([a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?:$|[^a-z0-9_-])`)

// ESD DNS servers for multi-DNS consistency check (matching Python ESD).
var esdDNSServers = []string{
	"223.5.5.5:53",       // AliDNS
	"119.29.29.29:53",    // DNSPod
	"202.101.224.69:53",  // BaiduDNS
}

var esdStableDNSServers = []string{"119.29.29.29:53"} // DNSPod as stable reference

type esdState struct {
	domain               string
	wildcard             bool
	wildcardIPs          []string
	wildcardSub          string
	wildcardSubDeep      string
	wildcardHTML         string
	wildcardHTMLDeep     string
	wildcardHTMLLen      int
	wildcardHTMLDeepLen  int
	requestHeaders       map[string]string
	rscRatio             float64
	discovered           *OrderedSet
	rsPending            *OrderedSet
	rsProcessed          *OrderedSet
	onlySimilarity       bool
	dnsServers           []string
	multiresolve         bool
}

func (a *App) collectHTTPSCertificateSubdomains(ctx context.Context, domain string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	host := "www." + domain
	if strings.HasPrefix(strings.ToLower(domain), "www.") {
		host = domain
	}

	tlsCtx, tlsCancel := context.WithTimeout(ctx, 5*time.Second)
	defer tlsCancel()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var conn *tls.Conn
	var dialErr error
	done := make(chan struct{})
	go func() {
		conn, dialErr = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		close(done)
	}()
	select {
	case <-done:
	case <-tlsCtx.Done():
		return nil, tlsCtx.Err()
	}
	if dialErr != nil {
		return nil, dialErr
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := NewOrderedSet()
	for _, cert := range state.PeerCertificates {
		for _, name := range cert.DNSNames {
			name = strings.TrimSpace(strings.TrimPrefix(name, "*."))
			if name != "" {
				result.Add(name)
			}
		}
	}
	return filterSubdomainsForDomain(domain, result.Items()), nil
}

// === OneForAll module equivalents ===

// collectHackerTargetSubdomains queries api.hackertarget.com (free, no API key).
func (a *App) bruteForceSubdomains(ctx context.Context, domain string) ([]string, error) {
	dict, err := a.loadESDDict()
	if err != nil {
		return nil, err
	}

	state := a.newESDState(domain)
	if err := a.prepareESDState(ctx, state); err != nil {
		return nil, err
	}

	result := state.discovered

	// DNS brute force (skip if only_similarity mode: all DNS results differ between servers).
	if !state.onlySimilarity {
		inputs := make(chan string, 1024)
		outputs := make(chan string, 1024)
		workers := 8
		if workers > len(dict) {
			workers = len(dict)
		}
		if workers < 1 {
			workers = 1
		}

		var wg sync.WaitGroup
		lookupCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resolver := goResolver
				for sub := range inputs {
					select {
					case <-lookupCtx.Done():
						return
					default:
					}

					host := domain
					if sub != "@" {
						host = sub + "." + domain
					}

					// Retry DNS query up to 4 times (matching Python ESD).
					var ips []string
					for attempt := 0; attempt < 2; attempt++ {
						recordCtx, recordCancel := context.WithTimeout(lookupCtx, 3*time.Second)
						res, err := resolver.LookupHost(recordCtx, host)
						recordCancel()
						if err == nil {
							ips = trimAndDedupe(res)
							break
						}
						// Definitive NXDOMAIN — no retry.
						if isNXDomain(err) {
							break
						}
						if attempt == 1 {
							a.progress.Log("[ESD] DNS 重试 %d 次仍失败: %s (%v)", attempt+1, host, err)
						}
					}
					if len(ips) == 0 {
						continue
					}
					if state.shouldDeferToRSC(host, ips) {
						continue
					}
					select {
					case outputs <- host:
					case <-lookupCtx.Done():
						return
					}
				}
			}()
		}

		go func() {
			defer close(inputs)
			for _, sub := range dict {
				select {
				case inputs <- sub:
				case <-lookupCtx.Done():
					return
				}
			}
		}()

		go func() {
			wg.Wait()
			close(outputs)
		}()

		for host := range outputs {
			result.Add(host)
		}
	}

	// CA certificate subdomains (matching Python ESD CAInfo).
	if extras, err := a.collectHTTPSCertificateSubdomains(ctx, domain); err == nil {
		for _, sub := range extras {
			// Resolve CA subdomains through DNS too.
			ips, _ := a.resolveIPv4s(ctx, sub)
			if len(ips) > 0 {
				if !state.shouldDeferToRSC(sub, ips) {
					result.Add(sub)
				}
			}
		}
	}

	// DNS Transfer Vulnerability (matching Python ESD DNSTransfer).
	if extras, err := a.collectZoneTransferSubdomains(ctx, domain); err == nil {
		for _, sub := range extras {
			ips, _ := a.resolveIPv4s(ctx, sub)
			if len(ips) > 0 {
				if !state.shouldDeferToRSC(sub, ips) {
					result.Add(sub)
				}
			}
		}
	}

	// Multiresolve: TXT/SOA/MX/AAAA records (matching Python ESD DNSQuery).
	if state.multiresolve {
		a.progress.Log("[ESD] 开始 multiresolve (TXT/SOA/MX/AAAA)...")
		recordSubs := a.collectDNSRecordSubdomains(ctx, domain, result.Items())
		for _, sub := range recordSubs {
			ips, _ := a.resolveIPv4s(ctx, sub)
			if len(ips) > 0 {
				if !state.shouldDeferToRSC(sub, ips) {
					result.Add(sub)
				}
			}
		}
	}

	// RSC: Response Similarity Comparison for wildcard domains.
	if state.wildcard {
		if err := a.runESDRSC(ctx, state, dict); err != nil {
			return nil, err
		}
	}

	// RS loop: redirect/response domain chain (matching Python ESD RS phase).
	if len(state.rsPending.Items()) > 0 {
		a.progress.Log("[ESD] 进入 RS(redirect/response) 阶段，待处理 %d 个", state.rsPending.Len())
	}
	for {
		pending := state.rsPending.Items()
		if len(pending) == 0 {
			break
		}
		state.rsPending = NewOrderedSet()
		for _, host := range pending {
			host = strings.Trim(strings.ToLower(host), ".")
			if host == "" || !state.rsProcessed.Add(host) {
				continue
			}
			ok, err := a.esdSimilarityCheck(ctx, state, host)
			if err != nil {
				continue
			}
			if ok {
				state.discovered.Add(host)
			}
		}
	}

	return filterSubdomainsForDomain(domain, result.Items()), nil
}

func (a *App) loadESDDict() ([]string, error) {
	a.esdDictOnce.Do(func() {
		path := filepath.Join(a.rootDir, "lib", "ESD", "subs.esd")
		file, err := os.Open(path)
		if err != nil {
			a.esdDictErr = err
			return
		}
		defer file.Close()

		set := NewOrderedSet()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, expanded := range expandESDTemplate(line) {
				set.Add(strings.Trim(expanded, "."))
			}
		}
		if err := scanner.Err(); err != nil {
			a.esdDictErr = err
			return
		}
		set.Add("@")
		a.esdDict = set.Items()
	})
	return a.esdDict, a.esdDictErr
}

func expandESDTemplate(line string) []string {
	if !strings.Contains(line, "{letter}") && !strings.Contains(line, "{number}") {
		return []string{strings.Trim(line, ".")}
	}

	var out []string
	var walk func(string)
	walk = func(current string) {
		switch {
		case strings.Contains(current, "{letter}"):
			for _, ch := range "abcdefghijklmnopqrstuvwxyz" {
				walk(strings.Replace(current, "{letter}", string(ch), 1))
			}
		case strings.Contains(current, "{number}"):
			for _, ch := range "0123456789" {
				walk(strings.Replace(current, "{number}", string(ch), 1))
			}
		default:
			current = strings.Trim(current, ".-")
			current = collapseHyphenRuns(current)
			if current != "" {
				out = append(out, current)
			}
		}
	}
	walk(line)
	return out
}

func collapseHyphenRuns(value string) string {
	for strings.Contains(value, "--") {
		value = strings.ReplaceAll(value, "--", "-")
	}
	return value
}

func (a *App) newESDState(domain string) *esdState {
	now := time.Now().UnixNano()
	return &esdState{
		domain:           domain,
		wildcardSub:      fmt.Sprintf("baiyan-esd-%d", now),
		wildcardSubDeep:  fmt.Sprintf("baiyan-esd-%d.%d", now, now%9973+1),
		requestHeaders:   map[string]string{"User-Agent": "Baiduspider", "Accept-Encoding": "gzip, deflate", "Referer": "http://www.baidu.com/"},
		rscRatio:         0.8,
		discovered:       NewOrderedSet(),
		rsPending:        NewOrderedSet(),
		rsProcessed:      NewOrderedSet(),
		onlySimilarity:   false,
		dnsServers:       esdDNSServers,
		multiresolve:     true,
	}
}

func (a *App) prepareESDState(ctx context.Context, state *esdState) error {
	// Multi-DNS consistency check (matching Python ESD behavior).
	stableDNSResults := make([][]string, 0, len(state.dnsServers))
	lastResults := []string(nil)
	wildcardIPsFromStable := []string(nil)

	for _, dnsServer := range state.dnsServers {
		if !checkDNSServer(dnsServer, 3*time.Second) {
			a.progress.Log("[ESD] DNS 服务器不可用，跳过: %s", dnsServer)
			continue
		}

		resolver := newResolver(dnsServer, 3*time.Second)
		wildcardHost := state.wildcardSub + "." + state.domain
		resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := resolver.LookupHost(resolveCtx, wildcardHost)
		cancel()
		if err != nil {
			stableDNSResults = append(stableDNSResults, nil)
			continue
		}
		sortedIPs := trimAndDedupe(ips)
		sort.Strings(sortedIPs)
		stableDNSResults = append(stableDNSResults, sortedIPs)

		// Use stable DNS server result as wildcard_ips.
		for _, stable := range esdStableDNSServers {
			if dnsServer == stable && len(sortedIPs) > 0 {
				wildcardIPsFromStable = sortedIPs
			}
		}

		// Check result consistency between DNS servers.
		if len(sortedIPs) > 0 {
			if len(lastResults) > 0 && !equalStringSlices(sortedIPs, lastResults) {
				state.onlySimilarity = true
				state.wildcard = true
				a.progress.Log("[ESD] DNS 结果不一致，标记为随机解析泛域名")
			}
			lastResults = sortedIPs
		}
	}

	// Check if all stable DNS results agree.
	if len(stableDNSResults) > 0 {
		firstResult := stableDNSResults[0]
		allStable := true
		for _, r := range stableDNSResults {
			if !equalStringSlices(r, firstResult) {
				allStable = false
				break
			}
		}
		if !allStable {
			a.progress.Log("[ESD] DNS 结果不完全一致，使用默认稳定 DNS")
		}
	}

	// Determine wildcard status.
	allNil := true
	for _, r := range stableDNSResults {
		if r != nil && len(r) > 0 {
			allNil = false
			break
		}
	}
	if !allNil || state.onlySimilarity {
		state.wildcard = true
	} else {
		state.wildcard = false
		return nil
	}

	// Set wildcard IPs.
	if len(wildcardIPsFromStable) > 0 {
		state.wildcardIPs = wildcardIPsFromStable
	} else if len(stableDNSResults) > 0 && stableDNSResults[0] != nil {
		state.wildcardIPs = stableDNSResults[0]
	}

	a.progress.Log("[ESD] 泛域名IP: %v", state.wildcardIPs)

	// Fetch wildcard HTML for RSC comparison.
	if html, err := a.fetchESDPage(ctx, state.wildcardSub+"."+state.domain, state.requestHeaders); err == nil {
		state.wildcardHTML = cleanESDHTML(html)
		state.wildcardHTMLLen = len(state.wildcardHTML)
	}
	if html, err := a.fetchESDPage(ctx, state.wildcardSubDeep+"."+state.domain, state.requestHeaders); err == nil {
		state.wildcardHTMLDeep = cleanESDHTML(html)
		state.wildcardHTMLDeepLen = len(state.wildcardHTMLDeep)
	}
	a.progress.Log("[ESD] 泛域名HTML长度: %d (二级: %d)", state.wildcardHTMLLen, state.wildcardHTMLDeepLen)
	return nil
}

// checkDNSServer sends a test DNS query to verify the server is reachable.
func checkDNSServer(server string, timeout time.Duration) bool {
	msg := []byte{
		0x5c, 0x6d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x05, 'b', 'a', 'i', 'd', 'u', 0x03, 'c', 'o', 'm',
		0x00, 0x00, 0x01, 0x00, 0x01,
	}

	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	_, err = conn.Read(buf)
	return err == nil
}

// newResolver creates a net.Resolver that uses a specific DNS server.
func newResolver(dnsServer string, timeout time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
}

func (s *esdState) shouldDeferToRSC(host string, ips []string) bool {
	if !s.wildcard {
		return false
	}
	if host == s.wildcardSub+"."+s.domain {
		return false
	}
	if len(ips) == 0 {
		return false
	}
	if equalStringSlices(ips, s.wildcardIPs) || isSubsetStrings(ips, s.wildcardIPs) {
		return true
	}
	return false
}

// realQuickRatio mimics Python difflib.SequenceMatcher.real_quick_ratio().
// realQuickRatio mimics Python difflib.SequenceMatcher.real_quick_ratio() using the
// Ratcliff/Obershelp algorithm: recursively finds longest common substrings and
// returns 2.0 * total_matches / (len(a) + len(b)).
func realQuickRatio(a, b string) float64 {
	if a == b {
		return 1.0
	}
	lenA, lenB := len(a), len(b)
	if lenA == 0 || lenB == 0 {
		return 0
	}
	matches := matchingBlocksSum(a, b)
	return 2.0 * float64(matches) / float64(lenA+lenB)
}

// matchingBlocksSum computes the sum of all matching block sizes using the
// Ratcliff/Obershelp algorithm: find the longest common substring, then
// recurse on the left and right remainders.
func matchingBlocksSum(a, b string) int {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	// Find longest common substring using DP (O(n*m) time, O(min(n,m)) space).
	bestI, bestJ, bestLen := 0, 0, 0
	shorter := len(a)
	if len(b) < shorter {
		shorter = len(b)
	}
	if shorter == 0 {
		return 0
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			if a[i-1] == b[j-1] {
				curr[j] = prev[j-1] + 1
				if curr[j] > bestLen {
					bestLen = curr[j]
					bestI = i - bestLen
					bestJ = j - bestLen
				}
			} else {
				curr[j] = 0
			}
		}
		prev, curr = curr, prev
	}
	if bestLen == 0 {
		return 0
	}
	return bestLen + matchingBlocksSum(a[:bestI], b[:bestJ]) + matchingBlocksSum(a[bestI+bestLen:], b[bestJ+bestLen:])
}

func (a *App) runESDRSC(ctx context.Context, state *esdState, dict []string) error {
	for _, sub := range dict {
		host := state.domain
		if sub != "@" {
			host = sub + "." + state.domain
		}
		ok, err := a.esdSimilarityCheck(ctx, state, host)
		if err != nil {
			continue
		}
		if ok {
			state.discovered.Add(host)
		}
	}

	for {
		pending := state.rsPending.Items()
		if len(pending) == 0 {
			return nil
		}
		state.rsPending = NewOrderedSet()
		for _, host := range pending {
			host = strings.Trim(strings.ToLower(host), ".")
			if host == "" || !state.rsProcessed.Add(host) {
				continue
			}
			ok, err := a.esdSimilarityCheck(ctx, state, host)
			if err != nil {
				continue
			}
			if ok {
				state.discovered.Add(host)
			}
		}
	}
}

func (a *App) esdSimilarityCheck(ctx context.Context, state *esdState, host string) (bool, error) {
	html, finalHost, err := a.fetchESDPageWithFinalHost(ctx, host, state.requestHeaders)
	if err != nil {
		return false, err
	}
	html = cleanESDHTML(html)

	// Process redirect/response domains for RS loop.
	if finalHost != "" {
		finalHost = strings.Trim(strings.ToLower(finalHost), ".")
		if finalHost != host && (finalHost == state.domain || strings.HasSuffix(finalHost, "."+state.domain)) {
			state.rsPending.Add(finalHost)
		}
	}

	for _, responseHost := range extractSameRootDomains(html, state.domain) {
		responseHost = strings.Trim(strings.ToLower(responseHost), ".")
		if responseHost == "" || responseHost == host {
			continue
		}
		if strings.HasSuffix(host, "."+state.domain) && responseHost != state.domain {
			if strings.Count(responseHost, ".") >= strings.Count(host, ".") && strings.HasSuffix(responseHost, "."+host) {
				continue
			}
		}
		state.rsPending.Add(responseHost)
	}

	if html == "" {
		return false, nil
	}

	// Choose baseline: secondary subdomain vs tertiary+ subdomain.
	baseline := state.wildcardHTML
	baselineLen := state.wildcardHTMLLen
	// domain is e.g. "example.com", secondary sub is "www.example.com" (1 extra dot level)
	if strings.Count(host, ".") > strings.Count(state.domain, ".")+1 {
		baseline = state.wildcardHTMLDeep
		baselineLen = state.wildcardHTMLDeepLen
	}
	if baseline == "" {
		baseline = state.wildcardHTML
		baselineLen = state.wildcardHTMLLen
	}
	if baseline == "" {
		return true, nil
	}

	// Fast path: same length = ratio 1 (matching Python ESD).
	htmlLen := len(html)
	var ratio float64
	if htmlLen == baselineLen {
		ratio = 1.0
	} else {
		ratio = realQuickRatio(html, baseline)
		ratio = mathRound(ratio, 3)
	}
	if ratio > state.rscRatio {
		return false, nil
	}

	return true, nil
}

func mathRound(val float64, decimals int) float64 {
	pow := 1.0
	for i := 0; i < decimals; i++ {
		pow *= 10
	}
	return float64(int(val*pow+0.5)) / pow
}

// isNXDomain checks if a DNS error means the domain definitely doesn't exist.
// In Python ESD: aiodns err_code 1 (no data) or 4 (domain name not found) = no retry.
func isNXDomain(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// collectDNSRecordSubdomains mimics Python ESD's DNSQuery: queries TXT/SOA/MX/AAAA
// records for each subdomain and extracts newly discovered domain names.
// Supports recursive discovery (matching Python DNSQuery recursion).
func (a *App) collectDNSRecordSubdomains(ctx context.Context, domain string, subdomains []string) []string {
	seen := NewOrderedSet()
	seen.AddMany(subdomains)
	baseSet := NewOrderedSet()
	baseSet.AddMany(subdomains)

	allResults := NewOrderedSet()

	// Iterative recursion (Python version uses recursion, we use loop to avoid stack overflow).
	for {
		newDomains := NewOrderedSet()
		for _, subdomain := range baseSet.Items() {
			select {
			case <-ctx.Done():
				return allResults.Items()
			default:
			}

			recordDomains := NewOrderedSet()

			// NS query
			nsCtx, nsCancel := context.WithTimeout(ctx, 5*time.Second)
			nsRecords, err := goResolver.LookupNS(nsCtx, subdomain)
			nsCancel()
			if err == nil {
				for _, ns := range nsRecords {
					recordDomains.Add(strings.TrimSuffix(strings.ToLower(ns.Host), "."))
				}
			}

			// SOA query
			if soaHosts, err := lookupSOA(ctx, subdomain); err == nil {
				recordDomains.AddMany(soaHosts)
			}

			// MX query
			mxCtx, mxCancel := context.WithTimeout(ctx, 5*time.Second)
			mxRecords, err := goResolver.LookupMX(mxCtx, subdomain)
			mxCancel()
			if err == nil {
				for _, mx := range mxRecords {
					recordDomains.Add(strings.TrimSuffix(strings.ToLower(mx.Host), "."))
				}
			}

			// TXT query
			txtCtx, txtCancel := context.WithTimeout(ctx, 5*time.Second)
			txtRecords, err := goResolver.LookupTXT(txtCtx, subdomain)
			txtCancel()
			if err == nil {
				for _, txt := range txtRecords {
					for _, match := range domainTokenRegexp.FindAllString(txt, -1) {
						recordDomains.Add(strings.Trim(strings.ToLower(match), "."))
					}
				}
			}

			// AAAA query
			aaaaCtx, aaaaCancel := context.WithTimeout(ctx, 5*time.Second)
			aaaaRecords, err := goResolver.LookupIPAddr(aaaaCtx, subdomain)
			aaaaCancel()
			if err == nil {
				for _, addr := range aaaaRecords {
					if addr.IP.To4() == nil && addr.IP.To16() != nil {
						// Extract domain from reverse lookup for IPv6
						names, err := goResolver.LookupAddr(ctx, addr.IP.String())
						if err == nil {
							for _, name := range names {
								recordDomains.Add(strings.TrimSuffix(strings.ToLower(name), "."))
							}
						}
					}
				}
			}

			// Filter: keep only domains under target domain, exclude self.
			for _, d := range recordDomains.Items() {
				d = strings.Trim(strings.ToLower(d), ".")
				if d == "" || d == subdomain {
					continue
				}
				if strings.HasSuffix(d, "."+domain) || d == domain {
					if !seen.Contains(d) {
						seen.Add(d)
						newDomains.Add(d)
					}
				}
			}
		}

		allResults.AddMany(newDomains.Items())
		if newDomains.Len() == 0 {
			break
		}
		baseSet = newDomains
	}
	return allResults.Items()
}

func (s *OrderedSet) Contains(value string) bool {
	_, ok := s.seen[value]
	return ok
}

// lookupSOA sends a raw SOA query and extracts rname/mname hosts.
func lookupSOA(ctx context.Context, domain string) ([]string, error) {
	msg := buildDNSQuery(domain, 6) // SOA type = 6
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	result := NewOrderedSet()
	// Extract domain-like patterns from SOA response.
	text := string(buf[:n])
	for _, match := range domainTokenRegexp.FindAllString(text, -1) {
		result.Add(strings.Trim(strings.ToLower(match), "."))
	}
	return result.Items(), nil
}

// buildDNSQuery builds a simple DNS query message for the given domain and qtype.
func buildDNSQuery(domain string, qtype uint16) []byte {
	id := uint16(time.Now().UnixNano())
	msg := make([]byte, 0, 512)
	msg = append(msg, byte(id>>8), byte(id))   // ID
	msg = append(msg, 0x01, 0x00)              // Flags: standard query
	msg = append(msg, 0x00, 0x01)              // QDCOUNT: 1 question
	msg = append(msg, 0x00, 0x00)              // ANCOUNT
	msg = append(msg, 0x00, 0x00)              // NSCOUNT
	msg = append(msg, 0x00, 0x00)              // ARCOUNT
	msg = append(msg, encodeDNSName(domain)...) // QNAME
	msg = append(msg, byte(qtype>>8), byte(qtype)) // QTYPE
	msg = append(msg, 0x00, 0x01)              // QCLASS: IN
	return msg
}

func (a *App) fetchESDPage(ctx context.Context, host string, headers map[string]string) (string, error) {
	body, _, err := a.fetchESDPageWithFinalHost(ctx, host, headers)
	return body, err
}

func (a *App) fetchESDPageWithFinalHost(ctx context.Context, host string, headers map[string]string) (string, string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+host, nil)
	if err != nil {
		return "", "", err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	finalHost := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalHost = resp.Request.URL.Hostname()
	}
	return string(body), finalHost, nil
}

func cleanESDHTML(data string) string {
	if data == "" {
		return ""
	}
	html := strings.Join(strings.Fields(data), "")
	// Go regexp 不支持 (?!) 负向前瞻，直接移除所有 script 标签
	scriptRe := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	return scriptRe.ReplaceAllString(html, "")
}

func extractSameRootDomains(html, domain string) []string {
	result := NewOrderedSet()
	if html == "" {
		return nil
	}
	html = strings.ToLower(html)
	domain = strings.ToLower(strings.Trim(domain, "."))
	re := regexp.MustCompile(`(?i)([a-z0-9][a-z0-9.-]*\.` + regexp.QuoteMeta(domain) + `)`)
	for _, match := range re.FindAllStringSubmatch(html, -1) {
		if len(match) < 2 {
			continue
		}
		result.Add(strings.Trim(match[1], "."))
	}
	return result.Items()
}

func equalStringSlices(a, b []string) bool {
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isSubsetStrings(values, superset []string) bool {
	if len(values) == 0 {
		return true
	}
	seen := make(map[string]struct{}, len(superset))
	for _, value := range superset {
		seen[value] = struct{}{}
	}
	for _, value := range values {
		if _, ok := seen[value]; !ok {
			return false
		}
	}
	return true
}

func (a *App) collectZoneTransferSubdomains(ctx context.Context, domain string) ([]string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	nsRecords, err := goResolver.LookupNS(reqCtx, domain)
	if err != nil || len(nsRecords) == 0 {
		return nil, err
	}

	result := NewOrderedSet()
	for _, ns := range nsRecords {
		host := strings.TrimSuffix(strings.TrimSpace(ns.Host), ".")
		if host == "" {
			continue
		}
		nsCtx, nsCancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := goResolver.LookupHost(nsCtx, host)
		nsCancel()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if subs, err := attemptAXFR(addr, domain); err == nil {
				result.AddMany(subs)
			}
		}
	}
	return filterSubdomainsForDomain(domain, result.Items()), nil
}

func attemptAXFR(addr, domain string) ([]string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, "53"), 4*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	queryID := uint16(time.Now().UnixNano())
	query := buildDNSAXFRQuery(queryID, domain)
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		return nil, err
	}
	msgLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
	if msgLen <= 0 || msgLen > 65535 {
		return nil, fmt.Errorf("AXFR 返回长度异常")
	}

	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}

	return extractDomainNamesFromDNSMessage(msg, domain), nil
}

func buildDNSAXFRQuery(id uint16, domain string) []byte {
	var msg []byte
	msg = append(msg, byte(id>>8), byte(id))
	msg = append(msg, 0x01, 0x00)
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	msg = append(msg, encodeDNSName(domain)...)
	msg = append(msg, 0x00, 0xFC)
	msg = append(msg, 0x00, 0x01)

	out := make([]byte, 0, len(msg)+2)
	out = append(out, byte(len(msg)>>8), byte(len(msg)))
	out = append(out, msg...)
	return out
}

func encodeDNSName(name string) []byte {
	name = strings.Trim(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out
}

func extractDomainNamesFromDNSMessage(msg []byte, domain string) []string {
	result := NewOrderedSet()
	text := string(msg)
	for _, match := range domainTokenRegexp.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		result.Add(strings.Trim(strings.ToLower(match[1]), "."))
	}
	return filterSubdomainsForDomain(domain, result.Items())
}

func filterSubdomainsForDomain(domain string, values []string) []string {
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	result := NewOrderedSet()
	for _, value := range values {
		host := strings.Trim(strings.ToLower(cleanHost(value)), ".")
		if host == "" {
			continue
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			result.Add(host)
		}
	}
	items := result.Items()
	sort.Strings(items)
	return items
}

func readBodyClose(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
