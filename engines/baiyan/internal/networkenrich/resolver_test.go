package networkenrich

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func testFailover(upstreams int) *FailoverResolver {
	r := &FailoverResolver{}
	for i := 0; i < upstreams; i++ {
		r.upstreams = append(r.upstreams, &net.Resolver{})
	}
	r.attempts = maxFailoverAttempts
	return r
}

var (
	errTimeout  = &net.DNSError{Err: "i/o timeout", Name: "a.example.com", IsTimeout: true}
	errServFail = &net.DNSError{Err: "server misbehaving", Name: "a.example.com", IsTemporary: true}
	errNXDomain = &net.DNSError{Err: "no such host", Name: "a.example.com", IsNotFound: true}
)

func TestFailoverMovesPastATimeoutAndServfail(t *testing.T) {
	r := testFailover(3)
	var asked []*net.Resolver
	answers := []error{errTimeout, errServFail, nil}
	value, err := failover(context.Background(), r, func(_ context.Context, upstream *net.Resolver) (string, error) {
		asked = append(asked, upstream)
		return "answer", answers[len(asked)-1]
	})
	if err != nil || value != "answer" || len(asked) != 3 {
		t.Fatalf("value=%q err=%v asked=%d", value, err, len(asked))
	}
	if asked[0] == asked[1] || asked[1] == asked[2] {
		t.Fatal("a retry asked the same upstream again")
	}
}

func TestFailoverStopsOnADefinitiveNegative(t *testing.T) {
	r := testFailover(3)
	calls := 0
	_, err := failover(context.Background(), r, func(context.Context, *net.Resolver) (string, error) {
		calls++
		return "", errNXDomain
	})
	if !definitive(err) || calls != 1 {
		t.Fatalf("NXDOMAIN is an answer, asked %d upstreams, err=%v", calls, err)
	}
}

func TestFailoverReturnsTheLastErrorWhenEveryAttemptFails(t *testing.T) {
	r := testFailover(5)
	calls := 0
	_, err := failover(context.Background(), r, func(context.Context, *net.Resolver) (string, error) {
		calls++
		return "", errTimeout
	})
	if !errors.Is(err, errTimeout) || calls != maxFailoverAttempts {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestEachAttemptHasItsOwnDeadline(t *testing.T) {
	r := testFailover(2)
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = failover(parent, r, func(ctx context.Context, _ *net.Resolver) (string, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > failoverAttemptTimeout {
			t.Fatalf("attempt deadline %v is not bounded by %v", time.Until(deadline), failoverAttemptTimeout)
		}
		return "", errTimeout
	})
}

func TestFailoverRotatesTheStartingUpstream(t *testing.T) {
	r := testFailover(3)
	first := map[*net.Resolver]bool{}
	for i := 0; i < 3; i++ {
		_, _ = failover(context.Background(), r, func(_ context.Context, upstream *net.Resolver) (string, error) {
			first[upstream] = true
			return "ok", nil
		})
	}
	if len(first) != 3 {
		t.Fatalf("lookups started on %d distinct upstreams, want 3", len(first))
	}
}

func TestFailoverHonoursCancellation(t *testing.T) {
	r := testFailover(3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := failover(ctx, r, func(context.Context, *net.Resolver) (string, error) {
		calls++
		return "", errTimeout
	})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestNewFailoverResolverParsesUpstreams(t *testing.T) {
	for raw, want := range map[string]string{
		"8.8.8.8":           "8.8.8.8:53",
		" 119.29.29.29 ":    "119.29.29.29:53",
		"223.5.5.5:5353":    "223.5.5.5:5353",
		"2001:db8::1":       "[2001:db8::1]:53",
		"[2001:db8::1]:853": "[2001:db8::1]:853",
	} {
		got, err := parseUpstream(raw)
		if err != nil || got != want {
			t.Fatalf("%q: got %q err %v", raw, got, err)
		}
	}
	for _, bad := range []string{"dns.example", "8.8.8.8:x", "300.1.1.1"} {
		if _, err := NewFailoverResolver([]string{bad}); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	r, err := NewFailoverResolver([]string{"119.29.29.29", "", "8.8.8.8"})
	if err != nil || r.Upstreams() != 2 || r.attempts != 2 {
		t.Fatalf("upstreams=%d attempts=%d err=%v", r.Upstreams(), r.attempts, err)
	}
}

func TestUnconfiguredResolverUsesTheSystemResolverWithOneRetry(t *testing.T) {
	r, err := NewFailoverResolver([]string{""})
	if err != nil || r.Upstreams() != 1 || r.upstreams[0] != net.DefaultResolver || r.attempts != 2 {
		t.Fatalf("upstreams=%d attempts=%d err=%v", r.Upstreams(), r.attempts, err)
	}
}
