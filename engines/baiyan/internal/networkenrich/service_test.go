package networkenrich

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeResolver struct {
	lookupIP    func(context.Context, string) ([]net.IPAddr, error)
	lookupCNAME func(context.Context, string) (string, error)
}

func (f fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f.lookupIP(ctx, host)
}
func (f fakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return f.lookupCNAME(ctx, host)
}

func requestFor(host string) Request {
	return Request{SchemaVersion: SchemaVersion, Items: []Input{{Key: "site-1", Host: host}}}
}

func TestEnrichPreservesFactsAndSeparatesExistingIPs(t *testing.T) {
	resolver := fakeResolver{
		lookupIP: func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host != "www.example.com." {
				t.Errorf("lookup must be absolute and normalized: %s", host)
			}
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}, {IP: net.ParseIP("2001:db8::10")}, {IP: net.ParseIP("203.0.113.10")}}, nil
		},
		lookupCNAME: func(context.Context, string) (string, error) { return "EDGE.CLOUDFRONT.NET.", nil },
	}
	request := requestFor(" WWW.Example.COM. ")
	request.Items[0].ObservedIPs = []string{"198.51.100.5"}
	response, err := New(resolver).Enrich(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	result := response.Items[0]
	if result.Host != "www.example.com" || result.Key != "site-1" || result.Status != "success" || len(result.ResolvedIPs) != 2 || strings.Contains(strings.Join(result.ResolvedIPs, ","), "198.51.100.5") {
		t.Fatalf("bad result: %+v", result)
	}
	if result.CDN.Provider != "Amazon CloudFront" || result.Cloud.Provider != "AWS" || len(result.CNAMEs) != 1 || result.CNAMEs[0] != "edge.cloudfront.net" {
		t.Fatalf("bad attribution: %+v", result)
	}
	if _, err := time.Parse(time.RFC3339Nano, result.ObservedAt); err != nil || result.RuleVersion != RuleVersion {
		t.Fatalf("missing provenance: %+v", result)
	}
}

func TestEnrichDistinguishesEmptyPartialAndFailure(t *testing.T) {
	for _, test := range []struct {
		name            string
		ipErr, cnameErr error
		status, kind    string
	}{
		{"empty answers", nil, nil, "success", ""},
		{"partial cname", errors.New("resolver details must not leak"), nil, "partial", "dns_error"},
		{"partial addresses", nil, context.DeadlineExceeded, "partial", "dns_timeout"},
		{"not found", &net.DNSError{IsNotFound: true}, &net.DNSError{IsNotFound: true}, "failed", "dns_not_found"},
		{"timeout", context.DeadlineExceeded, context.DeadlineExceeded, "failed", "dns_timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := fakeResolver{lookupIP: func(context.Context, string) ([]net.IPAddr, error) { return nil, test.ipErr }, lookupCNAME: func(context.Context, string) (string, error) { return "", test.cnameErr }}
			response, err := New(resolver).Enrich(context.Background(), requestFor("www.example.com"))
			if err != nil {
				t.Fatal(err)
			}
			result := response.Items[0]
			if result.Status != test.status || result.ErrorKind != test.kind || result.CDN.Status != "unknown" || result.Cloud.Status != "unknown" || result.ResolvedIPs == nil || result.CNAMEs == nil {
				t.Fatalf("bad result: %+v", result)
			}
		})
	}
}

func TestEnrichValidatesWholeBatchBeforeDNS(t *testing.T) {
	resolver := fakeResolver{lookupIP: func(context.Context, string) ([]net.IPAddr, error) { t.Error("unexpected DNS lookup"); return nil, nil }, lookupCNAME: func(context.Context, string) (string, error) { t.Error("unexpected DNS lookup"); return "", nil }}
	for _, host := range []string{"", "localhost", "svc.local", "a.localhost", "http://example.com", "example.com:80", "*.example.com", "a..com", "-x.example", "a.example/path", "example.com\nX:x", "127.0.0.1", "169.254.169.254", "224.0.0.1", "::", "::1", "fe80::1%en0", "999.1.1.1", strings.Repeat("a", 64) + ".example"} {
		request := requestFor("valid.example")
		request.Items = append(request.Items, Input{Key: "invalid", Host: host})
		if _, err := New(resolver).Enrich(context.Background(), request); err == nil {
			t.Errorf("accepted %q", host)
		}
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.SchemaVersion = "2" }, func(r *Request) { r.Items = nil },
		func(r *Request) { r.Items = append(r.Items, r.Items[0]) },
		func(r *Request) { r.Items[0].Key = "\n" },
		func(r *Request) { r.Items[0].ObservedIPs = []string{"169.254.169.254"} },
		func(r *Request) { r.Items[0].Fingerprints = []string{strings.Repeat("x", 129)} },
		func(r *Request) { r.Items[0].ObservedIPs = make([]string, 33) },
		func(r *Request) { r.Items[0].Fingerprints = make([]string, 33) },
		func(r *Request) { r.Items = make([]Input, 21) },
	} {
		request := requestFor("valid.example")
		mutate(&request)
		if _, err := New(resolver).Enrich(context.Background(), request); err == nil {
			t.Error("accepted invalid request")
		}
	}
}

func TestIPAddressInputDoesNotTriggerLookupOrInventCurrentDNS(t *testing.T) {
	resolver := fakeResolver{lookupIP: func(context.Context, string) ([]net.IPAddr, error) { t.Error("unexpected DNS lookup"); return nil, nil }, lookupCNAME: func(context.Context, string) (string, error) { t.Error("unexpected DNS lookup"); return "", nil }}
	for _, address := range []string{"192.168.2.5", "2001:db8::1", "203.0.113.10"} {
		response, err := New(resolver).Enrich(context.Background(), requestFor(address))
		if err != nil || len(response.Items) != 1 || len(response.Items[0].ResolvedIPs) != 0 || response.Items[0].Status != "success" {
			t.Fatalf("IP input: %+v %v", response, err)
		}
	}
}

func TestTargetTimeoutCancelsResolver(t *testing.T) {
	resolver := fakeResolver{lookupIP: func(ctx context.Context, _ string) ([]net.IPAddr, error) { <-ctx.Done(); return nil, ctx.Err() }, lookupCNAME: func(ctx context.Context, _ string) (string, error) { return "", ctx.Err() }}
	service := New(resolver)
	service.targetTimeout = 10 * time.Millisecond
	start := time.Now()
	response, err := service.Enrich(context.Background(), requestFor("www.example.com"))
	if err != nil || response.Items[0].ErrorKind != "dns_timeout" || time.Since(start) > time.Second {
		t.Fatalf("timeout not bounded: %+v %v", response, err)
	}
}

func TestBatchDeadlineAndRequestCancellation(t *testing.T) {
	var calls int32
	resolver := fakeResolver{lookupIP: func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		atomic.AddInt32(&calls, 1)
		<-ctx.Done()
		return nil, ctx.Err()
	}, lookupCNAME: func(ctx context.Context, _ string) (string, error) { return "", ctx.Err() }}
	service := New(resolver)
	service.batchTimeout = 20 * time.Millisecond
	request := requestFor("www.example.com")
	for i := 1; i < MaxItems; i++ {
		request.Items = append(request.Items, Input{Key: fmt.Sprint(i), Host: fmt.Sprintf("host%d.example", i)})
	}
	start := time.Now()
	response, err := service.Enrich(context.Background(), request)
	if err != nil || len(response.Items) != 20 || time.Since(start) > time.Second || atomic.LoadInt32(&calls) > 4 {
		t.Fatalf("batch not bounded: %v calls=%d", err, calls)
	}
	for _, result := range response.Items {
		if result.Status != "failed" || result.ErrorKind != "dns_timeout" {
			t.Fatalf("missing deadline status: %+v", result)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	atomic.StoreInt32(&calls, 0)
	response, err = service.Enrich(ctx, request)
	if err != nil || atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("cancelled request still looked up: %v calls=%d", err, calls)
	}
	for _, result := range response.Items {
		if result.ErrorKind != "cancelled" {
			t.Fatalf("bad cancelled result %+v", result)
		}
	}
}

func TestConcurrencyIsBoundedAcrossBatchesAndKeepsInputOrder(t *testing.T) {
	var active, peak int32
	enter := func() {
		current := atomic.AddInt32(&active, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if current <= old || atomic.CompareAndSwapInt32(&peak, old, current) {
				break
			}
		}
	}
	resolver := fakeResolver{lookupIP: func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		enter()
		defer atomic.AddInt32(&active, -1)
		select {
		case <-time.After(time.Millisecond):
		case <-ctx.Done():
		}
		return nil, nil
	}, lookupCNAME: func(context.Context, string) (string, error) { return "", nil }}
	service := New(resolver)
	var batches sync.WaitGroup
	for batch := 0; batch < 3; batch++ {
		batches.Add(1)
		go func() {
			defer batches.Done()
			request := Request{SchemaVersion: SchemaVersion}
			for i := 0; i < 20; i++ {
				request.Items = append(request.Items, Input{Key: fmt.Sprint(i), Host: fmt.Sprintf("host%d.example", i)})
			}
			response, err := service.Enrich(context.Background(), request)
			if err != nil {
				t.Error(err)
				return
			}
			for i, result := range response.Items {
				if result.Key != fmt.Sprint(i) {
					t.Errorf("order lost: %d %+v", i, result)
				}
			}
		}()
	}
	batches.Wait()
	if peak > 4 || peak < 2 {
		t.Fatalf("unexpected lookup concurrency: %d", peak)
	}
}

func TestAttributionHasDomainBoundariesAndEvidence(t *testing.T) {
	for _, test := range []struct{ name, cdn, cloud string }{
		{"X.CLOUDFRONT.NET.", "Amazon CloudFront", "AWS"},
		{"x.akamaiedge.net", "Akamai", ""}, {"x.edgekey.net", "Akamai", ""}, {"x.edgesuite.net", "Akamai", ""},
		{"x.cloudflare.net", "Cloudflare", ""}, {"x.amazonaws.com", "", "AWS"}, {"x.azurewebsites.net", "", "Azure"},
		{"x.cloudapp.net", "", "Azure"}, {"x.aliyuncs.com", "", "阿里云"}, {"x.myqcloud.com", "", "腾讯云"},
		{"evilcloudfront.net", "", ""}, {"cloudfront.net.evil.example", "", ""}, {"x.example", "", ""},
	} {
		cdn, cloud := Classify([]string{test.name}, nil)
		if cdn.Provider != test.cdn || cloud.Provider != test.cloud {
			t.Errorf("%s: %+v %+v", test.name, cdn, cloud)
		}
		for _, value := range []Attribution{cdn, cloud} {
			if value.Provider != "" && (value.Status != "identified" || len(value.Evidence) != 1) {
				t.Errorf("missing evidence: %+v", value)
			}
			if value.Provider == "" && value.Status != "unknown" {
				t.Errorf("invented negative: %+v", value)
			}
		}
	}
	cdn, cloud := Classify(nil, []string{"fake-cloudflare", "nginx"})
	if cdn.Status != "unknown" || cloud.Status != "unknown" {
		t.Fatal("substring fingerprint matched")
	}
	cdn, _ = Classify(nil, []string{"CLOUDFLARE"})
	if cdn.Provider != "Cloudflare" || !strings.HasPrefix(cdn.Evidence[0], "Supplied scanner fingerprint:") {
		t.Fatalf("missing fingerprint provenance: %+v", cdn)
	}
	cdn, _ = Classify([]string{"x.cloudfront.net"}, []string{"Cloudflare"})
	if cdn.Provider != "Amazon CloudFront" {
		t.Fatal("fingerprint overrode DNS evidence")
	}
}
