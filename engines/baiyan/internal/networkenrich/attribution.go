package networkenrich

import "strings"

func unknown() Attribution { return Attribution{Status: "unknown"} }

// Classify reports evidence of an edge or cloud service. It makes no assertion
// about the origin server and does not infer negative attribution from no match.
func Classify(cnames, fingerprints []string) (Attribution, Attribution) {
	cdn, cloud := unknown(), unknown()
	for _, name := range cnames {
		value := strings.TrimSuffix(strings.ToLower(name), ".")
		for _, rule := range []struct{ suffix, cdn, cloud string }{
			{"cloudfront.net", "Amazon CloudFront", "AWS"},
			{"akamaiedge.net", "Akamai", ""}, {"edgekey.net", "Akamai", ""}, {"edgesuite.net", "Akamai", ""},
			{"cloudflare.net", "Cloudflare", ""},
			{"amazonaws.com", "", "AWS"}, {"azurewebsites.net", "", "Azure"}, {"cloudapp.net", "", "Azure"},
			{"aliyuncs.com", "", "阿里云"}, {"myqcloud.com", "", "腾讯云"},
		} {
			if value != rule.suffix && !strings.HasSuffix(value, "."+rule.suffix) {
				continue
			}
			evidence := []string{"DNS canonical name: " + value}
			if rule.cdn != "" && cdn.Status == "unknown" {
				cdn = Attribution{Status: "identified", Provider: rule.cdn, Evidence: evidence}
			}
			if rule.cloud != "" && cloud.Status == "unknown" {
				cloud = Attribution{Status: "identified", Provider: rule.cloud, Evidence: evidence}
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
