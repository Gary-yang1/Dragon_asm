package networkenrich

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// failoverAttemptTimeout bounds one upstream's answer, so a slow server
	// leaves time for the next one instead of spending the lookup's budget.
	failoverAttemptTimeout = 2 * time.Second
	maxFailoverAttempts    = 3
	maxUpstreams           = 8
)

// FailoverResolver answers lookups from a list of upstream DNS servers, moving
// to the next server when one times out or fails. A definitive negative answer
// (NXDOMAIN, no data) ends the lookup: it is an answer, not a failure.
//
// The engine used the container's resolver, which forwards through Docker's
// embedded DNS to the host's resolver. On the test environment that chain took
// seconds or returned SERVFAIL for zones public resolvers answered in tens of
// milliseconds, so names with real answers were recorded as DNS failures.
type FailoverResolver struct {
	upstreams []*net.Resolver
	attempts  int
	next      atomic.Uint32
}

// NewFailoverResolver builds a resolver for servers given as "ip" or
// "ip:port". With no servers it uses the system resolver and retries a failed
// lookup once.
func NewFailoverResolver(servers []string) (*FailoverResolver, error) {
	resolver := &FailoverResolver{}
	for _, raw := range servers {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		address, err := parseUpstream(raw)
		if err != nil {
			return nil, err
		}
		dialer := net.Dialer{Timeout: failoverAttemptTimeout}
		resolver.upstreams = append(resolver.upstreams, &net.Resolver{
			PreferGo: true,
			// The Go resolver dials the address from resolv.conf; replace it
			// with this upstream for both UDP and its TCP fallback.
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, address)
			},
		})
	}
	if len(resolver.upstreams) > maxUpstreams {
		return nil, fmt.Errorf("networkenrich: at most %d DNS upstreams", maxUpstreams)
	}
	if len(resolver.upstreams) == 0 {
		resolver.upstreams = []*net.Resolver{net.DefaultResolver}
	}
	// Every lookup gets a second chance, even against one server; more servers
	// allow more attempts, up to the cap.
	resolver.attempts = len(resolver.upstreams)
	if resolver.attempts < 2 {
		resolver.attempts = 2
	}
	if resolver.attempts > maxFailoverAttempts {
		resolver.attempts = maxFailoverAttempts
	}
	return resolver, nil
}

func parseUpstream(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if address, err := netip.ParseAddrPort(raw); err == nil {
		return address.String(), nil
	}
	address, err := netip.ParseAddr(strings.Trim(raw, "[]"))
	if err != nil {
		return "", fmt.Errorf("networkenrich: DNS upstream %q is not an IP address or IP:port", raw)
	}
	return netip.AddrPortFrom(address, 53).String(), nil
}

// Upstreams reports how many servers the resolver rotates over.
func (r *FailoverResolver) Upstreams() int { return len(r.upstreams) }

func (r *FailoverResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return failover(ctx, r, func(ctx context.Context, upstream *net.Resolver) ([]net.IPAddr, error) {
		return upstream.LookupIPAddr(ctx, host)
	})
}

func (r *FailoverResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return failover(ctx, r, func(ctx context.Context, upstream *net.Resolver) (string, error) {
		return upstream.LookupCNAME(ctx, host)
	})
}

// definitive reports an error that is an answer: the name or record does not
// exist. Any other error says nothing about the name, so another upstream is
// asked.
func definitive(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func failover[T any](ctx context.Context, r *FailoverResolver, lookup func(context.Context, *net.Resolver) (T, error)) (T, error) {
	var zero T
	// Rotate the starting upstream so load spreads across servers.
	start := int(r.next.Add(1)-1) % len(r.upstreams)
	var lastErr error
	for attempt := 0; attempt < r.attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		upstream := r.upstreams[(start+attempt)%len(r.upstreams)]
		attemptCtx, cancel := context.WithTimeout(ctx, failoverAttemptTimeout)
		value, err := lookup(attemptCtx, upstream)
		cancel()
		if err == nil || definitive(err) {
			return value, err
		}
		lastErr = err
	}
	return zero, lastErr
}
