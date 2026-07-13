package job

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"baiyan/internal/contract"
)

type memoryStore struct {
	mu      sync.Mutex
	records map[string]Record
}

func newMemoryStore() *memoryStore { return &memoryStore{records: make(map[string]Record)} }

func (s *memoryStore) Save(record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.JobID] = record
	return nil
}

func (s *memoryStore) Get(jobID string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[jobID]
	if !ok {
		return Record{}, ErrNotFound
	}
	return record, nil
}

func (s *memoryStore) ListRecoverable() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]Record, 0)
	for _, record := range s.records {
		if record.Status == StatusQueued || record.Status == StatusRunning {
			items = append(items, record)
		}
	}
	return items, nil
}

type fakeExecutor struct {
	started chan struct{}
	release chan struct{}
	result  ExecutionResult
	err     error
}

type concurrentExecutor struct {
	started chan uint64
	release map[uint64]chan struct{}
}

func (e *concurrentExecutor) Execute(ctx context.Context, request contract.ScanRequest) (ExecutionResult, error) {
	e.started <- request.RunID
	select {
	case <-ctx.Done():
		return ExecutionResult{}, ctx.Err()
	case <-e.release[request.RunID]:
		return ExecutionResult{Status: StatusSuccess, ResultCount: request.RunID}, nil
	}
}

func (e *fakeExecutor) Execute(ctx context.Context, _ contract.ScanRequest) (ExecutionResult, error) {
	if e.started != nil {
		close(e.started)
	}
	if e.release != nil {
		select {
		case <-ctx.Done():
			return ExecutionResult{}, ctx.Err()
		case <-e.release:
		}
	}
	return e.result, e.err
}

func testRequest(runID uint64) contract.ScanRequest {
	return contract.ScanRequest{
		SchemaVersion: contract.SchemaVersion, RunID: runID, ProjectID: 1, ScopeID: 1,
		JobType: "passive_intel", Targets: []contract.Target{{Type: "domain", Value: "example.com"}},
		RateLimit: 10, Concurrency: 2, TimeoutSeconds: 30,
		CallbackURL: "https://asm.example.com/api/v1/discovery/callback?project_id=1&run_id=1",
		Options:     map[string]any{"profile": "subdomain_passive", "sources": []any{"certificate_transparency"}, "max_results": float64(100)},
	}
}

func TestSubmitIdempotencyAndConflict(t *testing.T) {
	store := newMemoryStore()
	executor := &fakeExecutor{release: make(chan struct{}), started: make(chan struct{})}
	service := NewService(store, executor, 10)
	if err := service.Start(1); err != nil {
		t.Fatal(err)
	}
	defer service.Shutdown()
	record, duplicate, err := service.Submit(testRequest(1), "1")
	if err != nil || duplicate || record.JobID != "job-1" {
		t.Fatalf("unexpected first submit: record=%+v duplicate=%v err=%v", record, duplicate, err)
	}
	<-executor.started
	_, duplicate, err = service.Submit(testRequest(1), "1")
	if err != nil || !duplicate {
		t.Fatalf("expected idempotent duplicate, duplicate=%v err=%v", duplicate, err)
	}
	changed := testRequest(1)
	changed.RateLimit = 11
	_, _, err = service.Submit(changed, "1")
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	close(executor.release)
}

func TestCancelPropagatesContext(t *testing.T) {
	store := newMemoryStore()
	executor := &fakeExecutor{release: make(chan struct{}), started: make(chan struct{})}
	service := NewService(store, executor, 10)
	if err := service.Start(1); err != nil {
		t.Fatal(err)
	}
	defer service.Shutdown()
	if _, _, err := service.Submit(testRequest(2), "2"); err != nil {
		t.Fatal(err)
	}
	<-executor.started
	record, err := service.Cancel("job-2")
	if err != nil || record.Status != StatusCancelled {
		t.Fatalf("cancel failed: record=%+v err=%v", record, err)
	}
	waitForStatus(t, service, "job-2", StatusCancelled)
}

func TestRunningJobRecoversAfterRestart(t *testing.T) {
	store := newMemoryStore()
	now := time.Now().UTC()
	_ = store.Save(Record{
		JobID: "job-3", IdempotencyKey: "3", RequestHash: "hash", Request: testRequest(3),
		Status: StatusRunning, CreatedAt: now, UpdatedAt: now,
	})
	executor := &fakeExecutor{result: ExecutionResult{Status: StatusSuccess, ResultCount: 4}}
	service := NewService(store, executor, 10)
	if err := service.Start(1); err != nil {
		t.Fatal(err)
	}
	defer service.Shutdown()
	waitForStatus(t, service, "job-3", StatusSuccess)
	record, _ := service.Get("job-3")
	if record.ResultCount != 4 {
		t.Fatalf("unexpected recovered result: %+v", record)
	}
}

func TestFileStorePersistsRecoverableRecord(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{JobID: "job-9", Status: StatusRunning, CreatedAt: time.Now().UTC()}
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	items, err := reopened.ListRecoverable()
	if err != nil || len(items) != 1 || items[0].JobID != "job-9" {
		t.Fatalf("unexpected recovery: items=%+v err=%v", items, err)
	}
}

func TestConcurrentJobsKeepIndependentState(t *testing.T) {
	store := newMemoryStore()
	executor := &concurrentExecutor{
		started: make(chan uint64, 2),
		release: map[uint64]chan struct{}{10: make(chan struct{}), 11: make(chan struct{})},
	}
	service := NewService(store, executor, 10)
	if err := service.Start(2); err != nil {
		t.Fatal(err)
	}
	defer service.Shutdown()
	for _, runID := range []uint64{10, 11} {
		if _, _, err := service.Submit(testRequest(runID), strconv.FormatUint(runID, 10)); err != nil {
			t.Fatal(err)
		}
	}
	started := map[uint64]bool{<-executor.started: true, <-executor.started: true}
	if !started[10] || !started[11] {
		t.Fatalf("jobs did not execute independently: %+v", started)
	}
	close(executor.release[11])
	waitForStatus(t, service, "job-11", StatusSuccess)
	first, err := service.Get("job-10")
	if err != nil || first.Status != StatusRunning {
		t.Fatalf("finishing job-11 changed job-10: %+v err=%v", first, err)
	}
	close(executor.release[10])
	waitForStatus(t, service, "job-10", StatusSuccess)
	first, _ = service.Get("job-10")
	second, _ := service.Get("job-11")
	if first.ResultCount != 10 || second.ResultCount != 11 {
		t.Fatalf("job results crossed: job-10=%+v job-11=%+v", first, second)
	}
}

func waitForStatus(t *testing.T, service *Service, jobID, status string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		record, err := service.Get(jobID)
		if err == nil && record.Status == status {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	record, _ := service.Get(jobID)
	t.Fatalf("job did not reach %s: %+v", status, record)
}
