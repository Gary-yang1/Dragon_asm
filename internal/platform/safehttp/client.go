// Package safehttp builds HTTP clients for calling operator-supplied URLs.
//
// A notification webhook is a URL a project member types in. Handing that to a
// default http.Client turns the platform into an SSRF proxy: the caller picks the
// destination, and the server reaches it from inside the network. This client
// closes the usual routes in — internal addresses, redirects to them, unbounded
// bodies, and unbounded time.
package safehttp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/netguard"
)

var (
	// ErrBlockedAddress is returned when a request resolves to a non-public address.
	ErrBlockedAddress = errors.New("safehttp: destination address is not permitted")
	// ErrBlockedScheme is returned for anything other than http/https.
	ErrBlockedScheme = errors.New("safehttp: only http and https are permitted")
	// ErrResponseTooLarge is returned when a response exceeds the configured cap.
	ErrResponseTooLarge = errors.New("safehttp: response too large")
)

// Defaults chosen for webhook delivery: long enough for a slow receiver, short
// enough that a hung endpoint cannot pin a worker.
const (
	DefaultTimeout       = 10 * time.Second
	DefaultDialTimeout   = 5 * time.Second
	DefaultMaxResponse   = 64 << 10
	defaultIdleConnCount = 8
)

// Config tunes the client. The zero value is safe and uses the defaults above.
type Config struct {
	Timeout     time.Duration
	DialTimeout time.Duration
	MaxResponse int64
}

func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	if c.MaxResponse <= 0 {
		c.MaxResponse = DefaultMaxResponse
	}
	return c
}

// NewClient returns an http.Client that refuses to connect to non-public
// addresses and never follows redirects.
//
// The address check runs in Dialer.Control, which fires after DNS resolution and
// immediately before connect, once per candidate address. Validating the
// hostname up front instead would be defeated by DNS rebinding: a name that
// resolves public at check time and to 169.254.169.254 microseconds later.
// Checking the address actually being dialled leaves no such window.
func NewClient(cfg Config) *http.Client {
	cfg = cfg.withDefaults()

	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddress(address)
		},
	}

	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			MaxIdleConns:          defaultIdleConnCount,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   cfg.DialTimeout,
			ResponseHeaderTimeout: cfg.Timeout,
			// A proxy would bypass the address check entirely, since the dial would
			// target the proxy rather than the destination.
			Proxy: nil,
		},
		// A 302 to http://169.254.169.254/ would otherwise be followed with the
		// address check applied only to the original host.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// checkDialAddress rejects a "host:port" whose host is not a public IP.
func checkDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable address", ErrBlockedAddress)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Control always receives a resolved literal; anything else is unexpected
		// and refused rather than trusted.
		return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
	}
	if netguard.IsDangerousAddr(addr) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
	}
	return nil
}

// ValidateURL checks a URL before it is stored, so an unusable webhook is
// rejected at configuration time rather than failing silently at delivery.
//
// This is a lexical pre-check only. It cannot be authoritative — a hostname's
// address can change between now and delivery — which is why the dial-time check
// above is the real control.
func ValidateURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%w: unparsable url", ErrBlockedScheme)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ErrBlockedScheme
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: missing host", ErrBlockedScheme)
	}
	if parsed.User != nil {
		// Credentials in the URL would be written to the rule and echoed back by
		// the read API.
		return fmt.Errorf("%w: credentials are not permitted in the url", ErrBlockedScheme)
	}
	host := parsed.Hostname()
	if addr, addrErr := netip.ParseAddr(host); addrErr == nil {
		if netguard.IsDangerousAddr(addr) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
		}
		return nil
	}
	if isLocalName(host) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
	}
	return nil
}

// isLocalName blocks names that resolve inside the deployment by convention.
// It mirrors the special-use suffixes the discovery scope validator rejects.
func isLocalName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || h == "" {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".localdomain", ".internal", ".home.arpa"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// ReadBounded reads at most limit bytes, reporting ErrResponseTooLarge when the
// body is longer. Webhook receivers echo arbitrary content; without a cap a
// hostile one could exhaust worker memory.
func ReadBounded(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultMaxResponse
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return data[:limit], ErrResponseTooLarge
	}
	return data, nil
}
