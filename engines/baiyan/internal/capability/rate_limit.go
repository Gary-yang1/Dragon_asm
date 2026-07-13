package capability

import (
	"context"
	"errors"
	"sync"
	"time"
)

type operationGate interface {
	Wait(context.Context) error
}

type intervalOperationGate struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newOperationGate(rateLimit int) (operationGate, error) {
	if rateLimit < 1 || rateLimit > 10000 {
		return nil, errors.New("baiyan passive: rate_limit must be between 1 and 10000 operations per second")
	}
	return &intervalOperationGate{interval: time.Second / time.Duration(rateLimit)}, nil
}

func (g *intervalOperationGate) Wait(ctx context.Context) error {
	g.mu.Lock()
	now := time.Now()
	readyAt := g.next
	if readyAt.Before(now) {
		readyAt = now
	}
	g.next = readyAt.Add(g.interval)
	g.mu.Unlock()

	delay := time.Until(readyAt)
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
