package job

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"baiyan/internal/contract"
)

var (
	ErrIdempotencyConflict = errors.New("baiyan job: idempotency conflict")
	ErrQueueUnavailable    = errors.New("baiyan job: queue unavailable")
	ErrNotCancellable      = errors.New("baiyan job: not cancellable")
)

type Service struct {
	store    Store
	executor Executor
	queue    chan string
	now      func() time.Time

	mu      sync.Mutex
	active  map[string]context.CancelFunc
	queued  map[string]bool
	rootCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewService(store Store, executor Executor, queueSize int) *Service {
	if queueSize < 1 {
		queueSize = 100
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		store: store, executor: executor, queue: make(chan string, queueSize),
		now: func() time.Time { return time.Now().UTC() }, active: make(map[string]context.CancelFunc),
		queued: make(map[string]bool), rootCtx: ctx, cancel: cancel,
	}
}

func (s *Service) Start(workers int) error {
	if s.store == nil || s.executor == nil {
		return errors.New("baiyan job: service is not configured")
	}
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	recoverable, err := s.store.ListRecoverable()
	if err != nil {
		s.cancel()
		s.wg.Wait()
		return err
	}
	for _, record := range recoverable {
		record.Status = StatusQueued
		record.Progress = 0
		record.ErrorSummary = ""
		record.UpdatedAt = s.now()
		if err := s.store.Save(record); err != nil {
			return err
		}
		if err := s.enqueue(record.JobID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Shutdown() {
	s.cancel()
	s.mu.Lock()
	for _, cancel := range s.active {
		cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Service) Submit(request contract.ScanRequest, idempotencyKey string) (Record, bool, error) {
	jobID := "job-" + strconv.FormatUint(request.RunID, 10)
	raw, err := json.Marshal(request)
	if err != nil {
		return Record{}, false, err
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, err := s.store.Get(jobID)
	if err == nil {
		if existing.IdempotencyKey != idempotencyKey || existing.RequestHash != hash {
			return Record{}, false, ErrIdempotencyConflict
		}
		if existing.Status == StatusQueued && !s.queued[jobID] {
			select {
			case s.queue <- jobID:
				s.queued[jobID] = true
			default:
				return existing, true, ErrQueueUnavailable
			}
		}
		return existing, true, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Record{}, false, err
	}
	now := s.now()
	record := Record{
		JobID: jobID, IdempotencyKey: idempotencyKey, RequestHash: hash, Request: request,
		Status: StatusQueued, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.Save(record); err != nil {
		return Record{}, false, err
	}
	select {
	case s.queue <- jobID:
		s.queued[jobID] = true
		return record, false, nil
	default:
		return record, false, ErrQueueUnavailable
	}
}

func (s *Service) Get(jobID string) (Record, error) { return s.store.Get(jobID) }

func (s *Service) Cancel(jobID string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.store.Get(jobID)
	if err != nil {
		return Record{}, err
	}
	if record.Status == StatusCancelled {
		return record, nil
	}
	if record.Status != StatusQueued && record.Status != StatusRunning {
		return Record{}, ErrNotCancellable
	}
	if cancel := s.active[jobID]; cancel != nil {
		cancel()
	}
	record.Status = StatusCancelled
	record.Progress = 100
	record.ErrorSummary = "cancelled"
	record.UpdatedAt = s.now()
	if err := s.store.Save(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Service) enqueue(jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queued[jobID] {
		return nil
	}
	select {
	case s.queue <- jobID:
		s.queued[jobID] = true
		return nil
	default:
		return ErrQueueUnavailable
	}
}

func (s *Service) worker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.rootCtx.Done():
			return
		case jobID := <-s.queue:
			s.run(jobID)
		}
	}
}

func (s *Service) run(jobID string) {
	s.mu.Lock()
	s.queued[jobID] = false
	record, err := s.store.Get(jobID)
	if err != nil || record.Status == StatusCancelled {
		s.mu.Unlock()
		return
	}
	timeout := time.Duration(record.Request.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(s.rootCtx, timeout)
	s.active[jobID] = cancel
	record.Status = StatusRunning
	record.Progress = 10
	record.UpdatedAt = s.now()
	_ = s.store.Save(record)
	s.mu.Unlock()

	result, execErr := s.executor.Execute(ctx, record.Request)
	ctxErr := ctx.Err()
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, jobID)
	latest, getErr := s.store.Get(jobID)
	if getErr != nil || latest.Status == StatusCancelled {
		return
	}
	latest.Progress = 100
	latest.UpdatedAt = s.now()
	latest.ResultCount = result.ResultCount
	latest.ErrorSummary = boundedSummary(result.ErrorSummary)
	switch {
	case errors.Is(ctxErr, context.Canceled):
		latest.Status = StatusCancelled
		latest.ErrorSummary = "cancelled"
	case errors.Is(ctxErr, context.DeadlineExceeded):
		latest.Status = StatusFailed
		latest.ErrorSummary = "job timed out"
	case execErr != nil:
		latest.Status = StatusFailed
		if latest.ErrorSummary == "" {
			latest.ErrorSummary = "job execution failed"
		}
	case result.Status == StatusSuccess || result.Status == StatusPartialSuccess || result.Status == StatusFailed || result.Status == StatusCancelled:
		latest.Status = result.Status
	default:
		latest.Status = StatusFailed
		latest.ErrorSummary = "executor returned invalid status"
	}
	_ = s.store.Save(latest)
}

func boundedSummary(value string) string {
	if len(value) > 1024 {
		return value[:1024]
	}
	return value
}

func ValidateIdempotencyKey(runID uint64, key string) error {
	if key != strconv.FormatUint(runID, 10) {
		return fmt.Errorf("%w: key must equal run_id", ErrIdempotencyConflict)
	}
	return nil
}
