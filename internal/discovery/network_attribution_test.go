package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
)

func TestAttributionRoleNeedsAnIdentifiedVersionedJudgement(t *testing.T) {
	edge := map[string]string{factAttrCDNStatus: "identified", factAttrIPRole: AttributionCDNEdge, factAttrRuleVersion: "cdn-rules-v2"}
	for _, tc := range []struct {
		name       string
		assetType  string
		attributes map[string]string
		want       string
	}{
		{"edge address", asset.TypeIP, edge, AttributionCDNEdge},
		{"served name", asset.TypeSubdomain, map[string]string{factAttrCDNStatus: "identified", factAttrRuleVersion: "cdn-rules-v2"}, AttributionCDNServed},
		{"address without edge role", asset.TypeIP, map[string]string{factAttrCDNStatus: "identified", factAttrRuleVersion: "cdn-rules-v2"}, ""},
		{"unversioned judgement", asset.TypeIP, map[string]string{factAttrCDNStatus: "identified", factAttrIPRole: AttributionCDNEdge}, ""},
		{"unknown is not no", asset.TypeIP, map[string]string{factAttrCDNStatus: "unknown"}, ""},
		{"no attributes", asset.TypeIP, nil, ""},
		{"web asset", asset.TypeWeb, edge, ""},
	} {
		if got := attributionRole(tc.assetType, tc.attributes); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestTruncateRunesKeepsUTF8Whole(t *testing.T) {
	if got := truncateRunes("阿里云CDN", 4); got != "阿" {
		t.Fatalf("got %q", got)
	}
	if got := truncateRunes("  Cloudflare  ", 128); got != "Cloudflare" {
		t.Fatalf("got %q", got)
	}
}

func TestDerivedIPTargetsRefuseCDNEdgesAndFlagSharedAddresses(t *testing.T) {
	repo := newFakeRepo()
	repo.ipNetwork = map[string]IPNetworkAttribution{
		"104.16.1.1":   {Value: "104.16.1.1", Role: AttributionCDNEdge, Provider: "Cloudflare"},
		"198.51.100.9": {Value: "198.51.100.9", ResolvedBy: 12},
		"198.51.100.1": {Value: "198.51.100.1", ResolvedBy: 1},
	}
	items := []DerivedTarget{
		{TargetType: TargetTypeIP, Value: "104.16.1.1", Status: "pending", Reason: "base"},
		{TargetType: TargetTypeIP, Value: "104.16.1.1", Status: "inherited", Reason: "base"},
		{TargetType: TargetTypeIP, Value: "198.51.100.9", Status: "pending", Reason: "base"},
		{TargetType: TargetTypeIP, Value: "198.51.100.1", Status: "pending", Reason: "base"},
		{TargetType: TargetTypeDomain, Value: "104.16.1.1", Status: "pending", Reason: "base"},
	}
	if err := applyIPNetwork(context.Background(), repo, 1, items); err != nil {
		t.Fatal(err)
	}
	for i, want := range []struct{ status, reason string }{
		{"excluded", "Cloudflare CDN 边缘节点，不是本单位资产，不能作为扫描目标"},
		{"excluded", "Cloudflare CDN 边缘节点，不是本单位资产，不能作为扫描目标"}, // even when the parent scope covers it
		{"pending", "base；疑似共享地址：被 12 个域名解析，确认前请核实是否为本单位地址"},
		{"pending", "base"},
		{"pending", "base"}, // only IP targets are looked up
	} {
		if items[i].Status != want.status || items[i].Reason != want.reason {
			t.Fatalf("item %d: %+v", i, items[i])
		}
	}
}

func TestActiveDispatchRefusesCDNEdgeWhateverTheOwnershipPolicy(t *testing.T) {
	repo := newFakeRepo()
	repo.ipNetwork = map[string]IPNetworkAttribution{"104.16.1.1": {Value: "104.16.1.1", Role: AttributionCDNEdge}}
	svc := NewService(repo)
	err := svc.refuseCDNEdgeTargets(context.Background(), 1, TaskTypePortProbe, []DispatchTarget{{Type: TargetTypeIP, Value: "198.51.100.1"}, {Type: TargetTypeIP, Value: "104.16.1.1"}})
	if !errors.Is(err, ErrActiveTargetCDNEdge) {
		t.Fatalf("CDN edge dispatched: %v", err)
	}
	if err := svc.refuseCDNEdgeTargets(context.Background(), 1, TaskTypePortProbe, []DispatchTarget{{Type: TargetTypeIP, Value: "198.51.100.1"}}); err != nil {
		t.Fatalf("own address refused: %v", err)
	}
	// Passive tasks send nothing to the target, so they are not gated.
	if err := svc.refuseCDNEdgeTargets(context.Background(), 1, TaskTypeDNS, []DispatchTarget{{Type: TargetTypeIP, Value: "104.16.1.1"}}); err != nil {
		t.Fatalf("passive task gated: %v", err)
	}
}
