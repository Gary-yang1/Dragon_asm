package asset

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Normalization errors. Callers (future import/discovery handlers) map these to
// 422/400 responses.
var (
	ErrInvalidType   = errors.New("asset: invalid asset_type")
	ErrEmptyValue    = errors.New("asset: empty value")
	ErrValueTooLong  = errors.New("asset: value too long")
	ErrKeyTooLong    = errors.New("asset: normalized key too long")
	ErrInvalidDomain = errors.New("asset: invalid domain")
	ErrInvalidIP     = errors.New("asset: invalid ip")
	ErrInvalidPort   = errors.New("asset: invalid port")
)

// Length bounds mirror the asset table column widths so oversized input is
// rejected at the service layer with a typed error rather than surfacing as an
// opaque DB truncation error.
const (
	// maxValueLen bounds the normalized value (value VARCHAR(1024)).
	maxValueLen = 1024
	// maxAssetKeyLen bounds the type-prefixed key (asset_key VARCHAR(512)).
	maxAssetKeyLen = 512
)

// hostLabel matches a single DNS label: alphanumeric with internal hyphens,
// 1..63 chars. A full hostname is one or more labels joined by dots.
var hostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Normalized is the canonical form of a raw asset input: a stable, type-prefixed
// Key (unique per project) and the normalized Value.
type Normalized struct {
	Type  string
	Key   string
	Value string
}

// Normalize canonicalizes (assetType, rawValue) into a Normalized key/value, or
// returns a typed error for invalid input. It never touches the database and is
// the single source of truth for what a "duplicate" asset is: two inputs that
// normalize to the same Key are the same asset within a project.
func Normalize(assetType, rawValue string) (Normalized, error) {
	if !IsValidType(assetType) {
		return Normalized{}, fmt.Errorf("%w: %q", ErrInvalidType, assetType)
	}
	v := strings.TrimSpace(rawValue)
	if v == "" {
		return Normalized{}, ErrEmptyValue
	}
	if len(v) > maxValueLen {
		return Normalized{}, ErrValueTooLong
	}

	var (
		n   Normalized
		err error
	)
	switch assetType {
	case TypeDomain, TypeSubdomain:
		n, err = normalizeDomain(assetType, v)
	case TypeIP:
		n, err = normalizeIP(v)
	case TypePort:
		n, err = normalizePort(v)
	default:
		// service/web/certificate/cloud_resource/third_party: minimal, stable
		// normalization (trim only, already done) until their own key rules land.
		n = Normalized{Type: assetType, Key: assetType + ":" + v, Value: v}
	}
	if err != nil {
		return Normalized{}, err
	}
	// The key carries the type prefix, so a value within maxValueLen can still
	// overflow asset_key (VARCHAR(512)); guard every type uniformly.
	if len(n.Key) > maxAssetKeyLen {
		return Normalized{}, ErrKeyTooLong
	}
	return n, nil
}

// normalizeDomain lowercases, strips a single trailing dot, and validates each
// DNS label. It rejects empty labels, over-length names, and illegal characters.
func normalizeDomain(assetType, v string) (Normalized, error) {
	host := strings.ToLower(strings.TrimSuffix(v, "."))
	if host == "" || len(host) > 253 {
		return Normalized{}, ErrInvalidDomain
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return Normalized{}, fmt.Errorf("%w: %q", ErrInvalidDomain, v)
		}
	}
	return Normalized{Type: assetType, Key: assetType + ":" + host, Value: host}, nil
}

// normalizeIP parses and re-serializes the IP into its canonical text form
// (e.g. compresses IPv6). net.ParseIP rejects ambiguous forms such as
// leading-zero IPv4 octets, so those are treated as invalid input.
func normalizeIP(v string) (Normalized, error) {
	ip := net.ParseIP(v)
	if ip == nil {
		return Normalized{}, fmt.Errorf("%w: %q", ErrInvalidIP, v)
	}
	canonical := ip.String()
	return Normalized{Type: TypeIP, Key: TypeIP + ":" + canonical, Value: canonical}, nil
}

// normalizePort parses "host:port", validates the host as an IP and the port as
// 1..65535, and produces a canonical "ip:port" value plus a "port:ip:port" key.
func normalizePort(v string) (Normalized, error) {
	host, portStr, err := net.SplitHostPort(v)
	if err != nil {
		return Normalized{}, fmt.Errorf("%w: %q", ErrInvalidPort, v)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return Normalized{}, fmt.Errorf("%w: %q", ErrInvalidIP, host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Normalized{}, fmt.Errorf("%w: %q", ErrInvalidPort, portStr)
	}
	canonical := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	return Normalized{Type: TypePort, Key: TypePort + ":" + canonical, Value: canonical}, nil
}
