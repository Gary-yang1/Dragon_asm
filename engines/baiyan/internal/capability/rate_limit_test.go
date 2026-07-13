package capability

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOperationGateValidatesRate(t *testing.T) {
	for _, rate := range []int{0, -1, 10001} {
		if _, err := newOperationGate(rate); err == nil {
			t.Fatalf("expected invalid rate rejection: %d", rate)
		}
	}
}

func TestOperationGateWaitIsCancellable(t *testing.T) {
	gate, err := newOperationGate(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err = gate.Wait(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("cancelled rate wait did not stop promptly")
	}
}

func TestOperationGatePacesOperationStarts(t *testing.T) {
	gate, err := newOperationGate(50)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := gate.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if elapsed < 15*time.Millisecond {
		t.Fatalf("rate gate started operations too quickly: %s", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("rate gate delayed operation unexpectedly: %s", elapsed)
	}
}
