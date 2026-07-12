package baiyan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════
// OneForAll Go 等价实现：搜索引擎 / SRV 爆破 / Finder / Altdns / Enrich
// ═══════════════════════════════════════════════════════════

// ——— 搜索引擎结果中提取 URL 的正则 ———
var searchURLRegexp = regexp.MustCompile(`https?://[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}`)

// ———————————————————————————————————————————————————————————
// 1. 搜索引擎 (Baidu + Bing)
// ———————————————————————————————————————————————————————————

// collectSearchEngineSubdomains queries Baidu and Bing with site:domain.
func (a *App) collectSearchEngineSubdomains(ctx context.Context, domain string) ([]string, error) {
	result := NewOrderedSet()
	var mu sync.Mutex
	var wg sync.WaitGroup

	searchers := []func(context.Context, string) ([]string, error){
		searchBaidu,
		searchBing,
	}

	for _, s := range searchers {
		wg.Add(1)
		go func(search func(context.Context, string) ([]string, error)) {
			defer wg.Done()
			if subs, err := search(ctx, domain); err == nil {
				mu.Lock()
				result.AddMany(subs)
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()
	return filterSubdomainsForDomain(domain, result.Items()), nil
}

func searchBaidu(ctx context.Context, domain string) ([]string, error) {
	query := url.QueryEscape(fmt.Sprintf("site:%s", domain))
	endpoint := fmt.Sprintf("https://www.baidu.com/s?wd=%s&rn=100", query)

	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return extractDomainsFromText(string(body), domain), nil
}

func searchBing(ctx context.Context, domain string) ([]string, error) {
	query := url.QueryEscape(fmt.Sprintf("site:%s", domain))
	endpoint := fmt.Sprintf("https://www.bing.com/search?q=%s&count=50", query)

	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return extractDomainsFromText(string(body), domain), nil
}

func extractDomainsFromText(text, domain string) []string {
	result := NewOrderedSet()
	text = strings.ToLower(text)

	// 正则匹配所有 URL
	urls := searchURLRegexp.FindAllString(text, -1)
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		host := parsed.Hostname()
		if strings.HasSuffix(host, "."+domain) || host == domain {
			result.Add(host)
		}
	}

	// 同时用 domainTokenRegexp 匹配裸域名
	matches := domainTokenRegexp.FindAllString(text, -1)
	for _, m := range matches {
		m = strings.TrimSpace(strings.ToLower(m))
		if strings.HasSuffix(m, "."+domain) || m == domain {
			result.Add(m)
		}
	}

	return result.Items()
}

// ———————————————————————————————————————————————————————————
// 2. SRV 记录爆破
// ———————————————————————————————————————————————————————————

var srvPrefixes = []string{
	"_ldap._tcp", "_gc._tcp", "_kerberos._tcp", "_kerberos._udp",
	"_kpasswd._tcp", "_kpasswd._udp", "_autodiscover._tcp",
	"_sip._tcp", "_sip._udp", "_sips._tcp", "_sipfederationtls._tcp",
	"_nicname._tcp", "_whois._tcp", "_caldav._tcp", "_carddav._tcp",
	"_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
	"_smtp._tcp", "_submission._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp",
	"_jabber._tcp", "_ftp._tcp", "_https._tcp", "_http._tcp", "_smtps._tcp",
	"_h323be._tcp", "_h323cs._tcp", "_sipinternal._tcp", "_sip._sctp",
	"_sip._tls", "_stun._tcp", "_stun._udp", "_turn._tcp", "_turn._udp",
	"_stuns._tcp", "_turns._tcp",
}

func (a *App) collectSRVSubdomains(ctx context.Context, domain string) ([]string, error) {
	result := NewOrderedSet()
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)

	for _, prefix := range srvPrefixes {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			srvCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			srvName := p + "." + domain
			_, addrs, err := goResolver.LookupSRV(srvCtx, "", "", srvName)
			if err != nil || len(addrs) == 0 {
				return
			}
			for _, addr := range addrs {
				target := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(addr.Target)), ".")
				if target == "" {
					continue
				}
				if strings.Contains(target, ".") {
					mu.Lock()
					result.Add(target)
					mu.Unlock()
				} else {
					mu.Lock()
					result.Add(target + "." + domain)
					mu.Unlock()
				}
			}
		}(prefix)
	}
	wg.Wait()
	return filterSubdomainsForDomain(domain, result.Items()), nil
}

// ———————————————————————————————————————————————————————————
// 3. Finder: HTTP 响应体 + JS 提取子域
// ———————————————————————————————————————————————————————————

// findSubdomainsInHTTPResponse probes a URL and extracts subdomains from response body.
func (a *App) findSubdomainsInHTTPResponse(ctx context.Context, targetURL string) []string {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 524288))
	htmlStr := string(body)
	hostname := req.URL.Hostname()
	domain := extractMainDomain(hostname)

	result := NewOrderedSet()

	// 1. domainTokenRegexp 匹配裸域名
	matches := domainTokenRegexp.FindAllString(htmlStr, -1)
	for _, m := range matches {
		m = strings.TrimSpace(strings.ToLower(m))
		if strings.HasSuffix(m, "."+domain) || m == domain {
			result.Add(m)
		}
	}

	// 2. 正则提取 HTML 属性中的 URL (href/src/action)
	attrURLRe := regexp.MustCompile(`(?:href|src|action)\s*=\s*["']([^"']+)["']`)
	for _, match := range attrURLRe.FindAllStringSubmatch(htmlStr, -1) {
		if len(match) < 2 {
			continue
		}
		u, err := url.Parse(match[1])
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if strings.HasSuffix(host, "."+domain) || host == domain {
			result.Add(host)
		}
	}

	return result.Items()
}

// multiPartSuffixes lists known multi-label public suffixes (2 labels) so registrable-
// domain extraction keeps one extra label for cases like "asd.com.cn", "b.gov.cn",
// "example.co.uk". Single-label TLDs (com, cn, net, ...) are handled implicitly.
// Curated set; extend as needed.
var multiPartSuffixes = map[string]bool{
	// China second-level domains
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"ac.cn": true, "mil.cn": true,
	"ah.cn": true, "bj.cn": true, "cq.cn": true, "fj.cn": true, "gd.cn": true,
	"gs.cn": true, "gx.cn": true, "gz.cn": true, "ha.cn": true, "hb.cn": true,
	"he.cn": true, "hi.cn": true, "hk.cn": true, "hl.cn": true, "hn.cn": true,
	"jl.cn": true, "js.cn": true, "jx.cn": true, "ln.cn": true, "mo.cn": true,
	"nm.cn": true, "nx.cn": true, "qh.cn": true, "sc.cn": true, "sd.cn": true,
	"sh.cn": true, "sn.cn": true, "sx.cn": true, "tj.cn": true, "tw.cn": true,
	"xj.cn": true, "xz.cn": true, "yn.cn": true, "zj.cn": true,
	// common international second-level domains
	"co.uk": true, "ac.uk": true, "gov.uk": true, "org.uk": true, "me.uk": true,
	"co.jp": true, "co.kr": true, "co.nz": true, "co.in": true, "co.za": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"com.tw": true, "org.tw": true, "net.tw": true,
	"com.hk": true, "org.hk": true, "net.hk": true, "edu.hk": true, "gov.hk": true,
	"com.sg": true, "org.sg": true, "net.sg": true, "edu.sg": true, "gov.sg": true,
}

// extractMainDomain extracts the registrable domain from a hostname, honoring
// multi-label public suffixes (e.g. asd.com.cn, example.co.uk).
func extractMainDomain(hostname string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	hostname = strings.Trim(hostname, ".")
	if hostname == "" {
		return ""
	}
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}
	if multiPartSuffixes[parts[len(parts)-2]+"."+parts[len(parts)-1]] {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// ———————————————————————————————————————————————————————————
// 4. Altdns: 子域置换生成 + DNS 验证
// ———————————————————————————————————————————————————————————

var altPermutations = []struct{ prefix, suffix string }{
	{"", "-dev"}, {"", "-staging"}, {"", "-test"}, {"", "-api"},
	{"", "-admin"}, {"", "-www"}, {"", "-web"}, {"", "-mail"},
	{"", "-cdn"}, {"", "-static"}, {"", "-assets"}, {"", "-img"},
	{"", "-app"}, {"", "-m"}, {"", "-mobile"}, {"", "-beta"},
	{"", "dev"}, {"", "test"}, {"", "api"}, {"", "admin"},
	{"dev-", ""}, {"test-", ""}, {"api-", ""}, {"admin-", ""},
	{"www-", ""}, {"m-", ""}, {"web-", ""}, {"mail-", ""},
}

// collectAltdnsSubdomains generates permutation subdomains and validates via DNS.
func (a *App) collectAltdnsSubdomains(ctx context.Context, domain string, knownSubs []string) []string {
	result := NewOrderedSet()
	candidates := NewOrderedSet()

	for _, sub := range knownSubs {
		prefix := strings.TrimSuffix(sub, "."+domain)
		for _, rule := range altPermutations {
			if rule.prefix != "" {
				candidates.Add(rule.prefix + prefix + rule.suffix + "." + domain)
			} else {
				candidates.Add(prefix + rule.suffix + "." + domain)
			}
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)

	for _, cand := range candidates.Items() {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			ips, err := goResolver.LookupIPAddr(dnsCtx, host)
			if err == nil && len(ips) > 0 {
				for _, ip := range ips {
					if ipv4 := ip.IP.To4(); ipv4 != nil {
						mu.Lock()
						result.Add(host)
						mu.Unlock()
						break
					}
				}
			}
		}(cand)
	}
	wg.Wait()
	return filterSubdomainsForDomain(domain, result.Items())
}

// ———————————————————————————————————————————————————————————
// 5. Enrich: IP 富化信息查询
// ———————————————————————————————————————————————————————————

// EnrichInfo holds IP enrichment details.
type EnrichInfo struct {
	IP      string
	ASN     string
	ISP     string
	Org     string
	Country string
	City    string
}

// queryIPInfo queries ip-api.com for ASN/ISP info (free, no key required).
func queryIPInfo(ctx context.Context, ip string) (*EnrichInfo, error) {
	endpoint := fmt.Sprintf("http://ip-api.com/json/%s?fields=as,isp,org,country,city", ip)
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	rawStr := string(body)

	var asn, isp, org, country, city string
	if strings.Contains(rawStr, `"as":"`) {
		asn = extractJSONStr(rawStr, "as")
		isp = extractJSONStr(rawStr, "isp")
		org = extractJSONStr(rawStr, "org")
		country = extractJSONStr(rawStr, "country")
		city = extractJSONStr(rawStr, "city")
	}
	return &EnrichInfo{IP: ip, ASN: asn, ISP: isp, Org: org, Country: country, City: city}, nil
}

func extractJSONStr(raw, key string) string {
	prefix := `"` + key + `":"`
	idx := strings.Index(raw, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	s := raw[start:]
	end := strings.Index(s, `"`)
	if end < 0 {
		return ""
	}
	return s[:end]
}

// ———————————————————————————————————————————————————————————
// 统一入口：替换 OneForAll Python 功能
// ———————————————————————————————————————————————————————————

// runOneForAllGo is the Go equivalent of the Python oneforall_collect.py.
// Returns aggregated subdomains from all OneForAll-equivalent sources.
func (a *App) runOneForAllGo(ctx context.Context, domain string) ([]string, error) {
	result := NewOrderedSet()
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if subs, err := a.collectSearchEngineSubdomains(ctx, domain); err == nil {
			mu.Lock()
			result.AddMany(subs)
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if subs, err := a.collectSRVSubdomains(ctx, domain); err == nil {
			mu.Lock()
			result.AddMany(subs)
			mu.Unlock()
		}
	}()

	wg.Wait()
	return filterSubdomainsForDomain(domain, result.Items()), nil
}
