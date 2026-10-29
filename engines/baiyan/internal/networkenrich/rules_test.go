package networkenrich

import "testing"

func TestRuleSetLoadsTheCLIData(t *testing.T) {
	set, err := loadedRules()
	if err != nil {
		t.Fatal(err)
	}
	// 540 OneForAll IPv4 ranges plus the published Cloudflare v4/v6 ranges.
	if len(set.ranges) != 540+len(cloudflareRanges) {
		t.Fatalf("ranges = %d", len(set.ranges))
	}
	for _, rule := range set.keywords {
		if genericKeywords[rule.keyword] || cloudOnlySuffix(rule.keyword) || rule.keyword == "" {
			t.Fatalf("keyword %q should have been dropped", rule.keyword)
		}
	}
	if RuleVersion != "cdn-rules-v2" {
		t.Fatalf("rule version = %s", RuleVersion)
	}
}

func TestClassifyNetworkAliasRules(t *testing.T) {
	for _, tc := range []struct {
		name, provider string
		identified     bool
	}{
		{"x.alicdn.com", "Alibaba Cloud", true},            // dotted keyword, label boundary
		{"a.chinacache.com.cn", "ChinaCache", true},        // word on the registrable label, two-part suffix
		{"d1.fastly.net", "Fastly", true},                  // word keyword
		{"edge.akamaitechnologies.com", "Akamai", true},    // word as a prefix of the registrable label
		{"d111.cloudfront.net", "Amazon CloudFront", true}, // curated suffix still wins
		{"img-cdn.example.com", "", false},                 // generic "cdn" is not evidence
		{"cache.example.com", "", false},                   // generic "cache"
		{"fastly.net.evil.example", "", false},             // provider word outside the registrable label
		{"evilfastly.net", "", false},                      // provider word not at the label start
		{"x.notalicdn.com", "", false},                     // dotted keyword needs a label boundary
		{"ns1.awsdns-01.com", "", false},                   // DNS hosting, not an edge
	} {
		cdn, _ := ClassifyNetwork([]string{tc.name}, nil, nil)
		if (cdn.Status == "identified") != tc.identified || cdn.Provider != tc.provider {
			t.Fatalf("%s: %+v", tc.name, cdn)
		}
		if tc.identified && len(cdn.Evidence) == 0 {
			t.Fatalf("%s: identified without evidence", tc.name)
		}
	}
}

func TestCloudHostingIsNotAnEdge(t *testing.T) {
	for name, cloudProvider := range map[string]string{"bucket.s3.amazonaws.com": "AWS", "img.oss-cn-hangzhou.aliyuncs.com": "阿里云"} {
		cdn, cloud := ClassifyNetwork([]string{name}, nil, nil)
		if cdn.Status != "unknown" || cloud.Provider != cloudProvider {
			t.Fatalf("%s: cdn=%+v cloud=%+v", name, cdn, cloud)
		}
	}
}

func TestClassifyNetworkAddressRanges(t *testing.T) {
	for _, tc := range []struct {
		ip, provider string
		identified   bool
	}{
		{"104.16.1.1", "Cloudflare", true},
		{"162.159.135.91", "Cloudflare", true},
		{"2606:4700:7::a29f:885b", "Cloudflare", true}, // IPv6, absent from the OneForAll list
		{"::ffff:104.16.1.1", "Cloudflare", true},      // IPv4-mapped form
		{"223.99.255.10", "", true},                    // OneForAll range: an edge, provider unnamed
		{"192.0.2.10", "", false},
		{"not-an-ip", "", false},
	} {
		got := ClassifyAddress(tc.ip)
		if (got.Status == "identified") != tc.identified || got.Provider != tc.provider {
			t.Fatalf("%s: %+v", tc.ip, got)
		}
	}
}

func TestAliasEvidenceOutranksAddressRange(t *testing.T) {
	cdn, _ := ClassifyNetwork([]string{"d1.fastly.net"}, []string{"104.16.1.1"}, nil)
	if cdn.Provider != "Fastly" {
		t.Fatalf("alias should win over a range: %+v", cdn)
	}
}
