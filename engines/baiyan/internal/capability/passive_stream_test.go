package capability

import (
	"baiyan/internal/contract"
	"baiyan/internal/job"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type observingSender struct {
	mu      sync.Mutex
	batches []contract.CallbackBatch
	found   chan struct{}
	once    sync.Once
}

func (s *observingSender) Send(_ context.Context, _ string, b contract.CallbackBatch, _ int) error {
	s.mu.Lock()
	s.batches = append(s.batches, b)
	s.mu.Unlock()
	for _, a := range b.Assets {
		if a.Value == "fast.example.com" {
			s.once.Do(func() { close(s.found) })
		}
	}
	return nil
}

type heldProvider struct{ release chan struct{} }

func (p heldProvider) Name() string { return "slow" }
func (p heldProvider) Discover(ctx context.Context, _ string) ([]string, error) {
	select {
	case <-p.release:
		return []string{"slow.example.com"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestPartialDiscoveriesArriveWhileAnotherSourceIsStillRunning(t *testing.T) {
	sender := &observingSender{found: make(chan struct{})}
	slow := heldProvider{release: make(chan struct{})}
	executor := NewPassiveExecutor([]PassiveProvider{slow, &fakeProvider{name: "fast", results: []string{"fast.example.com"}}}, nil, sender)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := executor.Execute(ctx, passiveRequest()); done <- err }()
	select {
	case <-sender.found:
	case <-ctx.Done():
		t.Fatal("no early result while source is blocked")
	}
	select {
	case err := <-done:
		t.Fatalf("completed before slow source: %v", err)
	default:
	}
	close(slow.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	for i, b := range sender.batches {
		if b.Seq != uint64(i+1) {
			t.Fatal("callback sequence gap")
		}
	}
}

type countingResolver struct{ hosts []string }

func (r *countingResolver) Resolve(_ context.Context, hosts []string, _ int, _ operationGate) ([]DNSResult, error) {
	r.hosts = append(r.hosts, hosts...)
	out := []DNSResult{}
	for _, host := range hosts {
		out = append(out, DNSResult{Host: host, Status: "no_records"})
	}
	return out, nil
}
func TestDNSProcessesAllDiscoveriesBeyondFiveHundred(t *testing.T) {
	found := []string{}
	for i := 0; i < 738; i++ {
		found = append(found, fmt.Sprintf("host%d.example.com", i))
	}
	resolver := &countingResolver{}
	sender := &fakeSender{}
	executor := NewPassiveExecutor([]PassiveProvider{&fakeProvider{name: "fofa", results: found}}, resolver, sender)
	executor.randomLabel = func() string { return "wildcard-probe" }
	request := passiveRequest()
	request.Options["max_results"] = 1000
	result, err := executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	// Every discovery is resolved, plus the wildcard probes for their one zone.
	resolved := 0
	for _, host := range resolver.hosts {
		if !strings.HasPrefix(host, "wildcard-probe.") {
			resolved++
		}
	}
	if result.Status != "success" || resolved != 738 || len(resolver.hosts) != 738+wildcardProbesPerZone {
		t.Fatalf("unexpected completion: %+v resolved=%d total=%d", result, resolved, len(resolver.hosts))
	}
	var last *contract.StageProgress
	for _, batch := range sender.batches {
		if batch.StageProgress != nil && batch.StageProgress.Stage == "dns" {
			last = batch.StageProgress
		}
	}
	if last == nil || last.Completed != 738 || last.NoRecords != 738 || last.Failed != 0 {
		t.Fatalf("wrong DNS counters: %+v", last)
	}
}
func TestStreamingRestartReplaysUncertainBatchThenUsesNewSequences(t *testing.T) {
	store, err := job.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := passiveRequest()
	if err = store.Save(job.Record{JobID: "job-7", Request: request, Status: job.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	batch := contract.CallbackBatch{RunID: 7, Seq: 1, Status: "running", ResultCount: 2}
	if _, _, err = store.PrepareCallback(7, batch); err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{}
	checkpoint, _ := NewCheckpointedBatchSender(store, sender)
	seq, count, done, err := checkpoint.ResumeStream(context.Background(), request)
	if err != nil || done != nil || seq != 2 || count != 2 || len(sender.batches) != 1 {
		t.Fatalf("unsafe resume: seq=%d count=%d done=%v err=%v", seq, count, done, err)
	}
	_, _, _, err = checkpoint.ResumeStream(context.Background(), request)
	if err != nil || len(sender.batches) != 1 {
		t.Fatal("acknowledged batch replayed twice")
	}
}
func TestStreamRetainsResultsReturnedTogetherWithProviderError(t *testing.T) {
	sender := &fakeSender{}
	executor := NewPassiveExecutor([]PassiveProvider{&fakeProvider{name: "fofa", results: []string{"fast.example.com"}, err: errors.New("api-key=do-not-leak")}}, nil, sender)
	result, err := executor.Execute(context.Background(), passiveRequest())
	if err != nil || result.Status != "partial_success" {
		t.Fatalf("%+v %v", result, err)
	}
	found := false
	for _, b := range sender.batches {
		for _, a := range b.Assets {
			found = found || a.Value == "fast.example.com"
		}
	}
	if !found {
		t.Fatal("partial provider data was discarded")
	}
	if result.ErrorSummary != "fofa: PROVIDER_UNAVAILABLE" {
		t.Fatal(result.ErrorSummary)
	}
}

type concurrencyProvider struct {
	name         string
	mu           *sync.Mutex
	active, peak *int
}

func (p concurrencyProvider) Name() string { return p.name }
func (p concurrencyProvider) Discover(ctx context.Context, _ string) ([]string, error) {
	p.mu.Lock()
	*p.active++
	if *p.active > *p.peak {
		*p.peak = *p.active
	}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); *p.active--; p.mu.Unlock() }()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Millisecond):
		return nil, nil
	}
}
func TestSourceCollectionHonorsTaskConcurrency(t *testing.T) {
	var mu sync.Mutex
	active, peak := 0, 0
	providers := []PassiveProvider{concurrencyProvider{"one", &mu, &active, &peak}, concurrencyProvider{"two", &mu, &active, &peak}}
	request := passiveRequest()
	request.Concurrency = 1
	_, err := NewPassiveExecutor(providers, nil, &fakeSender{}).Execute(context.Background(), request)
	if err != nil || peak != 1 {
		t.Fatalf("concurrency limit violated: peak=%d err=%v", peak, err)
	}
}
