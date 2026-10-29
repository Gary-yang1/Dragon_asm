// Package networkenrich enriches existing asset identities using DNS and bounded
// attribution rules. It does not probe websites or depend on a job/database.
package networkenrich

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	SchemaVersion   = "1.0"
	Capability      = "network_enrichment"
	MaxItems        = 20
	maxAddresses    = 32
	maxFingerprints = 32
	concurrency     = 4
)

type Request struct {
	SchemaVersion string  `json:"schema_version"`
	Items         []Input `json:"items"`
}

type Input struct {
	Key          string   `json:"key"`
	Host         string   `json:"host"`
	ObservedIPs  []string `json:"observed_ips,omitempty"`
	Fingerprints []string `json:"fingerprints,omitempty"`
}

type Attribution struct {
	Status   string   `json:"status"`
	Provider string   `json:"provider,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

type Result struct {
	Key         string      `json:"key"`
	Host        string      `json:"host"`
	Status      string      `json:"status"`
	ResolvedIPs []string    `json:"resolved_ips"`
	CNAMEs      []string    `json:"cname_chain"`
	CDN         Attribution `json:"cdn"`
	Cloud       Attribution `json:"cloud"`
	ObservedAt  string      `json:"observed_at"`
	RuleVersion string      `json:"rule_version"`
	ErrorKind   string      `json:"error_kind,omitempty"`
}

type Response struct {
	SchemaVersion string   `json:"schema_version"`
	Items         []Result `json:"items"`
}

type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupCNAME(context.Context, string) (string, error)
}

type Service struct {
	resolver      Resolver
	slots         chan struct{}
	targetTimeout time.Duration
	batchTimeout  time.Duration
}

func New(resolver Resolver) *Service {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Service{resolver: resolver, slots: make(chan struct{}, concurrency), targetTimeout: 3 * time.Second, batchTimeout: 15 * time.Second}
}

// Enrich validates the complete batch before any DNS lookup. A shared semaphore
// limits DNS work across concurrent HTTP requests, not only inside one batch.
func (s *Service) Enrich(ctx context.Context, request Request) (Response, error) {
	inputs, err := Validate(request)
	if err != nil {
		return Response{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.batchTimeout)
	defer cancel()
	response := Response{SchemaVersion: SchemaVersion, Items: make([]Result, len(inputs))}
	queue := make(chan int)
	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range queue {
				response.Items[index] = s.enrich(ctx, inputs[index])
			}
		}()
	}
	for index := range inputs {
		queue <- index
	}
	close(queue)
	workers.Wait()
	return response, nil
}

func (s *Service) enrich(ctx context.Context, input Input) Result {
	result := Result{Key: input.Key, Host: input.Host, Status: "success", ResolvedIPs: []string{}, CNAMEs: []string{}, CDN: unknown(), Cloud: unknown(), ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), RuleVersion: RuleVersion}
	if err := ctx.Err(); err != nil {
		result.Status, result.ErrorKind = "failed", errorKind(err)
		return result
	}
	if net.ParseIP(input.Host) != nil {
		// An input IP is an existing observation, not a new DNS answer. Neither
		// input host nor observed_ips are relabeled as currently resolved IPs.
		result.CDN, result.Cloud = Classify(nil, input.Fingerprints)
		return result
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		result.Status, result.ErrorKind = "failed", errorKind(ctx.Err())
		return result
	}
	if err := ctx.Err(); err != nil {
		result.Status, result.ErrorKind = "failed", errorKind(err)
		return result
	}
	lookup, cancel := context.WithTimeout(ctx, s.targetTimeout)
	defer cancel()
	ips, ipErr := s.resolver.LookupIPAddr(lookup, input.Host+".")
	canonical, cnameErr := s.resolver.LookupCNAME(lookup, input.Host+".")
	if ipErr == nil {
		seen := map[string]bool{}
		for _, address := range ips {
			value := address.IP.String()
			if validIP(address.IP) && !seen[value] && len(result.ResolvedIPs) < maxAddresses {
				seen[value] = true
				result.ResolvedIPs = append(result.ResolvedIPs, value)
			}
		}
		sort.Strings(result.ResolvedIPs)
	}
	if cnameErr == nil && strings.TrimSpace(canonical) != "" {
		name, err := normalizeHost(canonical)
		if err != nil || net.ParseIP(name) != nil {
			cnameErr = errors.New("invalid DNS answer")
		} else if name != input.Host {
			// net.Resolver returns the final canonical name, not every CNAME hop.
			result.CNAMEs = append(result.CNAMEs, name)
		}
	}
	result.CDN, result.Cloud = ClassifyNetwork(result.CNAMEs, result.ResolvedIPs, input.Fingerprints)
	switch {
	case ipErr != nil && cnameErr != nil:
		result.Status = "failed"
	case ipErr != nil || cnameErr != nil:
		result.Status = "partial"
	}
	if ipErr != nil {
		result.ErrorKind = errorKind(ipErr)
	} else if cnameErr != nil {
		result.ErrorKind = errorKind(cnameErr)
	}
	return result
}

func Validate(request Request) ([]Input, error) {
	if request.SchemaVersion != SchemaVersion || len(request.Items) == 0 || len(request.Items) > MaxItems {
		return nil, errors.New("schema_version must be 1.0 and items must contain 1 to 20 entries")
	}
	result := make([]Input, len(request.Items))
	keys := make(map[string]bool, len(request.Items))
	for index, input := range request.Items {
		if !validText(input.Key, 128) || keys[input.Key] {
			return nil, fmt.Errorf("items[%d].key is invalid or duplicated", index)
		}
		keys[input.Key] = true
		host, err := normalizeHost(input.Host)
		if err != nil {
			return nil, fmt.Errorf("items[%d].host must be a hostname or unicast IP address", index)
		}
		if len(input.ObservedIPs) > maxAddresses || len(input.Fingerprints) > maxFingerprints {
			return nil, fmt.Errorf("items[%d] has too many addresses or fingerprints", index)
		}
		for _, address := range input.ObservedIPs {
			if len(address) > 45 || !validIP(net.ParseIP(address)) {
				return nil, fmt.Errorf("items[%d].observed_ips contains an invalid address", index)
			}
		}
		for _, fingerprint := range input.Fingerprints {
			if !validText(fingerprint, 128) {
				return nil, fmt.Errorf("items[%d].fingerprints contains an invalid value", index)
			}
		}
		input.Host = host
		input.ObservedIPs = append([]string(nil), input.ObservedIPs...)
		input.Fingerprints = append([]string(nil), input.Fingerprints...)
		result[index] = input
	}
	return result, nil
}

func normalizeHost(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if ip := net.ParseIP(value); ip != nil {
		if validIP(ip) {
			return ip.String(), nil
		}
		return "", errors.New("unsafe IP")
	}
	if len(value) == 0 || len(value) > 253 || !strings.Contains(value, ".") || value == "localhost" || strings.HasSuffix(value, ".localhost") || strings.HasSuffix(value, ".local") {
		return "", errors.New("invalid hostname")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid hostname")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", errors.New("invalid hostname")
			}
		}
	}
	last := value[strings.LastIndex(value, ".")+1:]
	if strings.Trim(last, "0123456789") == "" {
		return "", errors.New("ambiguous numeric hostname")
	}
	return value, nil
}

func validIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func validText(value string, max int) bool {
	if strings.TrimSpace(value) == "" || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func errorKind(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var dns *net.DNSError
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return "dns_timeout"
	}
	if errors.As(err, &dns) && dns.IsNotFound {
		return "dns_not_found"
	}
	return "dns_error"
}
