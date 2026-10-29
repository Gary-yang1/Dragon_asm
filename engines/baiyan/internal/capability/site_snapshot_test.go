package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"baiyan/internal/contract"
)

type crawlingProvider struct {
	hosts []string
	sites []SiteSnapshot
}

func (p *crawlingProvider) Name() string { return "fofa" }
func (p *crawlingProvider) Discover(context.Context, string) ([]string, error) {
	return p.hosts, nil
}
func (p *crawlingProvider) DiscoverSites(context.Context, string) ([]string, []SiteSnapshot, error) {
	return p.hosts, p.sites, nil
}

func TestCrawledSitesBecomeWebExposuresOnAcceptedHosts(t *testing.T) {
	provider := &crawlingProvider{
		hosts: []string{"www.example.com", "evil.test"},
		sites: []SiteSnapshot{
			{Host: "www.example.com", Scheme: "https", Port: 443, Title: "Example \u0007Home\n", Server: "nginx"},
			{Host: "example.com", Scheme: "http", Port: 80, Title: "Root"},
			{Host: "evil.test", Scheme: "http", Port: 80, Title: "Out of scope"},
			{Host: "www.example.com", Scheme: "https", Port: 443, Title: "duplicate row"},
		},
	}
	sender := &fakeSender{}
	executor := NewPassiveExecutor([]PassiveProvider{provider}, &fakeResolver{}, sender)
	if _, err := executor.Execute(context.Background(), passiveRequest()); err != nil {
		t.Fatal(err)
	}
	exposures := map[string]contract.ExposureFact{}
	webAssets := map[string]bool{}
	contains := map[string]string{}
	for _, batch := range sender.batches {
		if n := batch.FactCount(); n > maxBatchFacts {
			t.Fatalf("batch of %d facts", n)
		}
		for _, item := range batch.Exposures {
			exposures[item.URL] = item
		}
		for _, item := range batch.Assets {
			if item.AssetType == "web" {
				webAssets[item.NaturalKey] = true
			}
		}
		for _, item := range batch.Relations {
			if item.RelationType == "contains" && len(item.To.NaturalKey) > 4 && item.To.NaturalKey[:4] == "web:" {
				contains[item.To.NaturalKey] = item.From.NaturalKey
			}
		}
	}
	if len(exposures) != 2 {
		t.Fatalf("exposures = %#v", exposures)
	}
	www := exposures["https://www.example.com:443"]
	if www.ExposureType != "web" || www.Name != "Example Home" || www.Value != "unknown" || www.Fingerprint != "nginx" ||
		www.Port != 443 || www.Protocol != "https" || www.ActiveProbe || www.Confidence != siteSnapshotConfidence ||
		www.Parent.NaturalKey != "web:https://www.example.com:443" {
		t.Fatalf("www exposure = %#v", www)
	}
	if !webAssets["web:https://www.example.com:443"] || !webAssets["web:http://example.com:80"] {
		t.Fatalf("web assets = %v", webAssets)
	}
	if contains["web:https://www.example.com:443"] != "subdomain:www.example.com" || contains["web:http://example.com:80"] != "domain:example.com" {
		t.Fatalf("host relations = %v", contains)
	}
	if _, leaked := exposures["http://evil.test:80"]; leaked {
		t.Fatal("out-of-scope site became a fact")
	}
}

func TestManyCrawledSitesStayWithinBatchLimit(t *testing.T) {
	provider := &crawlingProvider{}
	for i := 0; i < 400; i++ {
		host := fmt.Sprintf("h%d.example.com", i)
		provider.hosts = append(provider.hosts, host)
		provider.sites = append(provider.sites, SiteSnapshot{Host: host, Scheme: "http", Port: 80, Title: "t"})
	}
	sender := &fakeSender{}
	request := passiveRequest()
	request.Options["max_results"] = float64(1000)
	if _, err := NewPassiveExecutor([]PassiveProvider{provider}, &fakeResolver{}, sender).Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, batch := range sender.batches {
		if n := batch.FactCount(); n > maxBatchFacts {
			t.Fatalf("batch of %d facts", n)
		}
		total += len(batch.Exposures)
	}
	if total != 400 {
		t.Fatalf("exposures = %d", total)
	}
}

func TestCleanSnapshotTextKeepsUTF8Boundaries(t *testing.T) {
	// 示例 is 6 bytes, the space 1, Ａ 3: exactly 10, and the next rune would split.
	if got := cleanSnapshotText("示例\tＡＢＣ\x00网站", 10); got != "示例 Ａ" {
		t.Fatalf("clean = %q", got)
	}
	if got := cleanSnapshotText("ok\xff", 255); got != "ok" {
		t.Fatalf("invalid UTF-8 kept: %q", got)
	}
}

// siteSnapshotGolden is shared with ASM, whose callback validator must accept
// it (internal/discovery/callback_baiyan_contract_test.go). Regenerate with
// UPDATE_GOLDEN=1 after an intentional change to the site snapshot facts.
const siteSnapshotGolden = "../../../../internal/discovery/testdata/baiyan_site_snapshot_callback.json"

func TestSiteSnapshotCallbackMatchesASMContractFixture(t *testing.T) {
	provider := &crawlingProvider{
		hosts: []string{"www.example.com"},
		sites: []SiteSnapshot{{Host: "www.example.com", Scheme: "https", Port: 443, Title: "Example Home", Server: "nginx"}},
	}
	sender := &fakeSender{}
	executor := NewPassiveExecutor([]PassiveProvider{provider}, &fakeResolver{}, sender)
	fixed := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	executor.now = func() time.Time { return fixed }
	if _, err := executor.Execute(context.Background(), passiveRequest()); err != nil {
		t.Fatal(err)
	}
	var batch *contract.CallbackBatch
	for i := range sender.batches {
		if len(sender.batches[i].Exposures) > 0 {
			batch = &sender.batches[i]
		}
	}
	if batch == nil {
		t.Fatal("no site snapshot batch sent")
	}
	got, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(siteSnapshotGolden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(siteSnapshotGolden)
	if err != nil {
		t.Fatalf("read golden (run with UPDATE_GOLDEN=1 to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("site snapshot callback changed; regenerate %s with UPDATE_GOLDEN=1 and keep ASM's validator in step:\n%s", siteSnapshotGolden, got)
	}
}
