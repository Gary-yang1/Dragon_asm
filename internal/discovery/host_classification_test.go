package discovery

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
)

func TestHostClassifierMatchesPassiveCollection(t *testing.T) {
	hosts := newHostClassifier([]string{"Example.com.", "portal.example.com", "example.jp"})
	for host, want := range map[string]string{
		"example.com":                asset.TypeDomain,    // scope root
		"app.example.com":            asset.TypeSubdomain, // under a root
		"portal.example.com":         asset.TypeDomain,    // a root that is itself a subdomain stays the root passive recorded
		"approve.portal.example.com": asset.TypeSubdomain,
		"WWW.SC.EXAMPLE.JP.":         asset.TypeSubdomain,
		"example.org":                asset.TypeDomain, // outside every root: public suffix list decides
		"shop.example.org":           asset.TypeSubdomain,
		"example.co.uk":              asset.TypeDomain,
		"www.example.co.uk":          asset.TypeSubdomain,
		"baidu.com.cn":               asset.TypeDomain,
		"notexample.com":             asset.TypeDomain, // suffix match needs a label boundary
	} {
		assert.Equal(t, want, hosts.assetType(host), host)
	}
}

// Active web probing used to key every host as "domain:", so a host passive
// collection had already recorded as a subdomain appeared twice in the asset list.
func TestActiveWebHostUsesTheSubdomainKeyPassiveDiscoveryProduced(t *testing.T) {
	run := activeResultTestRun(TaskTypeWebProbe)
	payload, _, err := buildActiveResultPayload(run, EngineResultPage{
		TaskID: run.EngineJobID, Page: 1, PageSize: activeAPIResultPageSize,
		TotalTargets: 2, FinishedTargets: 2,
		WebResults: []EngineWebResult{
			{Target: "http://approve.portal.example.com", Port: 80, Fingerprints: []EngineWebFingerprint{{Name: "nginx", StatusCode: "200", Title: "Approve"}}},
			{Target: "https://example.com", Port: 443, Fingerprints: []EngineWebFingerprint{{Name: "nginx", StatusCode: "200", Title: "Example"}}},
		},
	}, time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), newHostClassifier([]string{"example.com"}))
	require.NoError(t, err)

	keys := map[string]bool{}
	for _, fact := range payload.Assets {
		keys[fact.NaturalKey] = true
	}
	assert.True(t, keys["subdomain:approve.portal.example.com"], "%v", keys)
	assert.True(t, keys["domain:example.com"], "%v", keys)
	assert.False(t, keys["domain:approve.portal.example.com"], "%v", keys)

	from := map[string]bool{}
	for _, relation := range payload.Relations {
		from[relation.From.NaturalKey] = true
	}
	assert.True(t, from["subdomain:approve.portal.example.com"], "%v", from)
}
