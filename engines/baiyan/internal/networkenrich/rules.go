package networkenrich

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// RuleVersion identifies the attribution rule set. Every judgement carries it so
// a stored tag can be traced to the rules that produced it.
const RuleVersion = "cdn-rules-v2"

// The OneForAll data files are the CDN lists the Baiyan CLI has always used
// (internal/baiyan CDNMatcher). They are embedded here so the engine service
// and its passive DNS stage judge with the same data instead of a second copy.
// Upstream: https://github.com/shmilylty/OneForAll (data/cdn_*.json).
var (
	//go:embed rules/oneforall_cdn_ip_cidr.json
	oneForAllCIDRs []byte
	//go:embed rules/oneforall_cdn_cname_keywords.json
	oneForAllKeywords []byte
)

// cloudflareRanges are Cloudflare's published edge ranges
// (https://www.cloudflare.com/ips-v4 and ips-v6). The OneForAll list is IPv4
// only and unnamed; these give the most common edge a provider and IPv6 cover.
var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// suffixRules are curated CNAME suffixes that name both a CDN and a cloud.
var suffixRules = []struct{ suffix, cdn, cloud string }{
	{"cloudfront.net", "Amazon CloudFront", "AWS"},
	{"akamaiedge.net", "Akamai", ""}, {"edgekey.net", "Akamai", ""}, {"edgesuite.net", "Akamai", ""},
	{"cloudflare.net", "Cloudflare", ""},
	{"amazonaws.com", "", "AWS"}, {"azurewebsites.net", "", "Azure"}, {"cloudapp.net", "", "Azure"},
	{"aliyuncs.com", "", "阿里云"}, {"myqcloud.com", "", "腾讯云"},
}

// genericKeywords occur in ordinary hostnames ("img-cdn.example.com") or name
// DNS hosting rather than an edge network. The CLI matched them as substrings;
// on their own they are not evidence that traffic is served by a CDN.
var genericKeywords = map[string]bool{
	"cdn": true, "cache": true, "awsdns": true, "dnsv1": true, "telefonica": true, "footprint": true,
}

type keywordRule struct {
	keyword, provider string
	// kind: "suffix" for dotted names ("alicdn.com"), "word" for a provider
	// word that must begin the registrable label ("cloudfront", "akamai").
	kind string
}

type rangeRule struct {
	prefix   netip.Prefix
	provider string
}

type ruleSet struct {
	keywords []keywordRule
	ranges   []rangeRule
}

var (
	loadRules sync.Once
	rules     ruleSet
	rulesErr  error
)

func loadedRules() (ruleSet, error) {
	loadRules.Do(func() { rules, rulesErr = buildRules(oneForAllCIDRs, oneForAllKeywords) })
	return rules, rulesErr
}

func buildRules(cidrData, keywordData []byte) (ruleSet, error) {
	var set ruleSet
	var cidrs []string
	if err := json.Unmarshal(cidrData, &cidrs); err != nil {
		return set, fmt.Errorf("networkenrich: CDN ranges: %w", err)
	}
	for _, value := range cloudflareRanges {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return set, fmt.Errorf("networkenrich: Cloudflare range %q: %w", value, err)
		}
		set.ranges = append(set.ranges, rangeRule{prefix: prefix.Masked(), provider: "Cloudflare"})
	}
	for _, value := range cidrs {
		// Malformed upstream entries are skipped, as the CLI does.
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(value)); err == nil {
			set.ranges = append(set.ranges, rangeRule{prefix: prefix.Masked()})
		}
	}
	var keywords map[string]string
	if err := json.Unmarshal(keywordData, &keywords); err != nil {
		return set, fmt.Errorf("networkenrich: CDN keywords: %w", err)
	}
	for raw, provider := range keywords {
		keyword := strings.ToLower(strings.TrimSpace(raw))
		if keyword == "" || genericKeywords[keyword] {
			continue
		}
		rule := keywordRule{keyword: keyword, provider: strings.TrimSpace(provider), kind: "word"}
		switch {
		case strings.HasSuffix(keyword, "."):
			// "adn.", "wac.", "wpc.", "yimg.": a bare short label anywhere in a
			// name is too easy to collide with or spoof to count as evidence.
			continue
		case strings.Contains(keyword, "."):
			if cloudOnlySuffix(keyword) {
				// amazonaws.com, aliyuncs.com: cloud hosting, not an edge. The
				// curated rules attribute them to the cloud only.
				continue
			}
			rule.kind = "suffix"
		}
		// A provider name that only repeats the keyword says nothing more.
		if rule.provider == raw || rule.provider == keyword {
			rule.provider = ""
		}
		set.keywords = append(set.keywords, rule)
	}
	// Deterministic order: the longest (most specific) keyword wins.
	sort.Slice(set.keywords, func(i, j int) bool {
		if len(set.keywords[i].keyword) != len(set.keywords[j].keyword) {
			return len(set.keywords[i].keyword) > len(set.keywords[j].keyword)
		}
		return set.keywords[i].keyword < set.keywords[j].keyword
	})
	return set, nil
}

func cloudOnlySuffix(name string) bool {
	for _, rule := range suffixRules {
		if rule.cdn == "" && (name == rule.suffix || strings.HasSuffix(name, "."+rule.suffix)) {
			return true
		}
	}
	return false
}

// secondLevelSuffixes are the two-label public suffixes CDN providers register
// under. The engine module has no dependencies, so instead of the full public
// suffix list this covers the registrable label for the names in the rule set.
var secondLevelSuffixes = map[string]bool{"com": true, "net": true, "org": true, "co": true, "gov": true, "edu": true, "ac": true}

// registrableLabel returns the label a registrant controls: "cloudfront" for
// d1.cloudfront.net, "chinacache" for a.chinacache.com.cn. Matching only this
// label keeps "cloudfront.net.evil.example" and "evilcloudfront.net" out.
func registrableLabel(name string) string {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return ""
	}
	index := len(labels) - 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && secondLevelSuffixes[labels[len(labels)-2]] {
		index = len(labels) - 3
	}
	return labels[index]
}

func (r keywordRule) matches(name string) bool {
	if r.kind == "suffix" {
		return name == r.keyword || strings.HasSuffix(name, "."+r.keyword)
	}
	return strings.HasPrefix(registrableLabel(name), r.keyword)
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// ClassifyNetwork is the single CDN and cloud attribution rule set. cnames are
// aliases outside the organisation's own names, ips are fresh DNS answers and
// fingerprints are scanner technology names. It never asserts a negative: no
// match stays "unknown", and a CDN judgement says nothing about the origin.
//
// Evidence is checked strongest first: curated CNAME suffixes, CNAME keywords,
// published or listed edge ranges, then a scanner fingerprint.
func ClassifyNetwork(cnames, ips, fingerprints []string) (Attribution, Attribution) {
	cdn, cloud := unknown(), unknown()
	names := make([]string, 0, len(cnames))
	for _, raw := range cnames {
		if name := normalizeName(raw); name != "" {
			names = append(names, name)
		}
	}
	for _, name := range names {
		for _, rule := range suffixRules {
			if name != rule.suffix && !strings.HasSuffix(name, "."+rule.suffix) {
				continue
			}
			evidence := []string{"DNS canonical name: " + name}
			if rule.cdn != "" && cdn.Status == "unknown" {
				cdn = Attribution{Status: "identified", Provider: rule.cdn, Evidence: evidence}
			}
			if rule.cloud != "" && cloud.Status == "unknown" {
				cloud = Attribution{Status: "identified", Provider: rule.cloud, Evidence: evidence}
			}
		}
	}
	set, err := loadedRules()
	if err == nil && cdn.Status == "unknown" {
		for _, name := range names {
			for _, rule := range set.keywords {
				if rule.matches(name) {
					cdn = Attribution{Status: "identified", Provider: rule.provider, Evidence: []string{"CDN alias keyword " + rule.keyword + ": " + name}}
					break
				}
			}
			if cdn.Status != "unknown" {
				break
			}
		}
	}
	if err == nil && cdn.Status == "unknown" {
		for _, raw := range ips {
			address, parseErr := netip.ParseAddr(strings.TrimSpace(raw))
			if parseErr != nil {
				continue
			}
			address = address.Unmap()
			for _, rule := range set.ranges {
				if rule.prefix.Contains(address) {
					cdn = Attribution{Status: "identified", Provider: rule.provider, Evidence: []string{"Address " + address.String() + " is in CDN range " + rule.prefix.String()}}
					break
				}
			}
			if cdn.Status != "unknown" {
				break
			}
		}
	}
	// A supplied scanner fingerprint is weaker evidence than DNS. Only exact
	// recognized CDN names are accepted, and its source remains explicit.
	if cdn.Status == "unknown" {
		for _, fingerprint := range fingerprints {
			provider := ""
			switch strings.ToLower(strings.TrimSpace(fingerprint)) {
			case "cloudflare":
				provider = "Cloudflare"
			case "akamai":
				provider = "Akamai"
			case "amazon cloudfront", "cloudfront":
				provider = "Amazon CloudFront"
			}
			if provider != "" {
				cdn = Attribution{Status: "identified", Provider: provider, Evidence: []string{"Supplied scanner fingerprint: " + strings.TrimSpace(fingerprint)}}
				break
			}
		}
	}
	return cdn, cloud
}

// ClassifyAddress reports whether one address is in a known CDN range. The
// passive DNS stage uses it to tag address facts with the same rule set.
func ClassifyAddress(ip string) Attribution {
	cdn, _ := ClassifyNetwork(nil, []string{ip}, nil)
	return cdn
}
