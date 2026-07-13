package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"baiyan/internal/contract"
)

type fakeProvider struct {
	name    string
	results []string
	err     error
	wait    bool
	seenCtx chan struct{}
}

func (p *fakeProvider) Name() string { return p.name }
func (p *fakeProvider) Discover(ctx context.Context, _ string) ([]string, error) {
	if p.wait {
		<-ctx.Done()
		close(p.seenCtx)
		return nil, ctx.Err()
	}
	return p.results, p.err
}

type fakeResolver struct {
	results []DNSResult
	err     error
}

func (r *fakeResolver) Resolve(ctx context.Context, hosts []string, _ int, gate operationGate) ([]DNSResult, error) {
	for range hosts {
		if err := gate.Wait(ctx); err != nil {
			return nil, err
		}
	}
	return r.results, r.err
}

type countingGate struct {
	calls int
}

func (g *countingGate) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g.calls++
	return nil
}

type fakeSender struct {
	batches []contract.CallbackBatch
}

func (s *fakeSender) Send(ctx context.Context, _ string, batch contract.CallbackBatch, _ int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.batches = append(s.batches, batch)
	return nil
}

func passiveRequest() contract.ScanRequest {
	return contract.ScanRequest{
		SchemaVersion: contract.SchemaVersion, RunID: 7, ProjectID: 3, ScopeID: 2,
		JobType: "passive_intel", Targets: []contract.Target{{Type: "domain", Value: "example.com"}},
		RateLimit: 10000, Concurrency: 2, TimeoutSeconds: 10, CallbackURL: "https://asm.example.com/callback",
		Options: map[string]any{"max_results": float64(100)},
	}
}

func TestPassiveExecutorSharesRateBudgetAcrossProviderAndDNS(t *testing.T) {
	gate := &countingGate{}
	executor := NewPassiveExecutor(
		[]PassiveProvider{
			&fakeProvider{name: "one", results: []string{"api.example.com"}},
			&fakeProvider{name: "two", results: []string{"api.example.com"}},
		},
		&fakeResolver{}, &fakeSender{},
	)
	executor.newGate = func(rate int) (operationGate, error) {
		if rate != 10000 {
			t.Fatalf("unexpected rate: %d", rate)
		}
		return gate, nil
	}
	_, err := executor.Execute(context.Background(), passiveRequest())
	if err != nil {
		t.Fatal(err)
	}
	if gate.calls != 3 {
		t.Fatalf("expected one shared budget with 3 operations, got %d", gate.calls)
	}
}

func TestPassiveVerticalSliceProducesAuthorizedGraph(t *testing.T) {
	sender := &fakeSender{}
	executor := NewPassiveExecutor(
		[]PassiveProvider{&fakeProvider{name: "mock-ct", results: []string{"api.example.com", "outside.invalid", "api.example.com"}}},
		&fakeResolver{results: []DNSResult{{Host: "api.example.com", IPs: []string{"192.0.2.10"}}}}, sender,
	)
	executor.now = func() time.Time { return time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC) }
	result, err := executor.Execute(context.Background(), passiveRequest())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "success" || result.ResultCount == 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(sender.batches) < 3 {
		t.Fatalf("expected started/progress/final callbacks: %+v", sender.batches)
	}
	for index, batch := range sender.batches {
		if batch.Seq != uint64(index+1) {
			t.Fatalf("non-monotonic seq: %+v", sender.batches)
		}
		if batch.ResultCount != uint64(batch.FactCount()) {
			t.Fatalf("result_count mismatch: %+v", batch)
		}
		for _, fact := range batch.Assets {
			if fact.ActiveProbe || fact.Value == "outside.invalid" {
				t.Fatalf("unsafe fact emitted: %+v", fact)
			}
		}
	}
	final := sender.batches[len(sender.batches)-1]
	if final.Phase != "completed" || final.Status != "success" {
		t.Fatalf("unexpected final: %+v", final)
	}
}

func TestProviderFailureProducesPartialSuccess(t *testing.T) {
	sender := &fakeSender{}
	executor := NewPassiveExecutor([]PassiveProvider{
		&fakeProvider{name: "good", results: []string{"api.example.com"}},
		&fakeProvider{name: "bad", err: errors.New("unavailable")},
	}, nil, sender)
	result, err := executor.Execute(context.Background(), passiveRequest())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "partial_success" {
		t.Fatalf("expected partial success, got %+v", result)
	}
	final := sender.batches[len(sender.batches)-1]
	if len(final.ProviderErrors) != 1 || final.ProviderErrors[0].Message == "unavailable" {
		t.Fatalf("provider error missing or leaked raw error: %+v", final.ProviderErrors)
	}
}

func TestRequestedProviderMustBeConfigured(t *testing.T) {
	sender := &fakeSender{}
	executor := NewPassiveExecutor([]PassiveProvider{
		&fakeProvider{name: "certificate_transparency", results: []string{"api.example.com"}},
	}, nil, sender)
	request := passiveRequest()
	request.Options["sources"] = []any{"certificate_transparency", "fofa"}
	result, err := executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "partial_success" {
		t.Fatalf("missing provider was silently treated as success: %+v", result)
	}
	final := sender.batches[len(sender.batches)-1]
	if len(final.ProviderErrors) != 1 || final.ProviderErrors[0].Provider != "fofa" || final.ProviderErrors[0].Code != "PROVIDER_NOT_CONFIGURED" {
		t.Fatalf("unexpected missing-provider evidence: %+v", final.ProviderErrors)
	}
}

func TestDNSProfileHonorsRecordTypesWithoutFollowingResolvedIPs(t *testing.T) {
	sender := &fakeSender{}
	executor := NewPassiveExecutor(nil, &fakeResolver{results: []DNSResult{{
		Host: "example.com", IPs: []string{"192.0.2.10", "2001:db8::10"}, CNAMEs: []string{"alias.example.com"},
	}}}, sender)
	request := passiveRequest()
	request.JobType = "dns"
	request.Options = map[string]any{"profile": "resolve", "record_types": []any{"A"}, "max_results": float64(100)}
	result, err := executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "success" {
		t.Fatalf("unexpected DNS result: %+v", result)
	}
	values := make(map[string]bool)
	relationTypes := make(map[string]bool)
	for _, batch := range sender.batches {
		for _, asset := range batch.Assets {
			values[asset.Value] = true
		}
		for _, relation := range batch.Relations {
			relationTypes[relation.RelationType] = true
		}
	}
	if !values["192.0.2.10"] || values["2001:db8::10"] || values["alias.example.com"] {
		t.Fatalf("record_types filter drifted: %+v", values)
	}
	if relationTypes["cname_to"] {
		t.Fatalf("CNAME relation emitted when only A was requested: %+v", relationTypes)
	}
}

func TestCancelPropagatesToProviderAndStopsCallbacks(t *testing.T) {
	provider := &fakeProvider{name: "slow", wait: true, seenCtx: make(chan struct{})}
	sender := &fakeSender{}
	executor := NewPassiveExecutor([]PassiveProvider{provider}, nil, sender)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := executor.Execute(ctx, passiveRequest())
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-provider.seenCtx:
	case <-time.After(time.Second):
		t.Fatal("provider did not observe cancellation")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
