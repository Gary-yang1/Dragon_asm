package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type HTTPPassiveProvider struct {
	name    string
	baseURL *url.URL
	token   string
	client  *http.Client
	max     int
}

func NewHTTPPassiveProvider(name, baseURL, token string, client *http.Client, maxResults int) (*HTTPPassiveProvider, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("baiyan provider: invalid base URL")
	}
	if name == "" {
		return nil, errors.New("baiyan provider: name is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	client = withoutRedirects(client)
	if maxResults < 1 || maxResults > 1000 {
		maxResults = 500
	}
	return &HTTPPassiveProvider{name: name, baseURL: parsed, token: strings.TrimSpace(token), client: client, max: maxResults}, nil
}

func (p *HTTPPassiveProvider) Name() string { return p.name }

func (p *HTTPPassiveProvider) Discover(ctx context.Context, rootDomain string) ([]string, error) {
	target := *p.baseURL
	query := target.Query()
	query.Set("domain", rootDomain)
	query.Set("limit", "1000")
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, errors.New("baiyan provider: non-success response")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("baiyan provider: response exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("baiyan provider: response contains extra JSON")
	}
	if len(payload.Subdomains) > p.max {
		payload.Subdomains = payload.Subdomains[:p.max]
	}
	return payload.Subdomains, nil
}

type NetResolver struct {
	resolver *net.Resolver
	timeout  time.Duration
}

type HTTPResolver struct {
	baseURL *url.URL
	token   string
	client  *http.Client
	max     int
}

func NewHTTPResolver(baseURL, token string, client *http.Client, maxResults int) (*HTTPResolver, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("baiyan DNS provider: invalid URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	client = withoutRedirects(client)
	if maxResults < 1 || maxResults > 500 {
		maxResults = 500
	}
	return &HTTPResolver{baseURL: parsed, token: strings.TrimSpace(token), client: client, max: maxResults}, nil
}

func withoutRedirects(client *http.Client) *http.Client {
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clientCopy
}

func (r *HTTPResolver) Resolve(ctx context.Context, hosts []string, _ int, gate operationGate) ([]DNSResult, error) {
	if len(hosts) > r.max {
		hosts = hosts[:r.max]
	}
	results := make([]DNSResult, 0, len(hosts))
	var hadError bool
	for _, host := range hosts {
		if err := gate.Wait(ctx); err != nil {
			return results, err
		}
		target := *r.baseURL
		query := target.Query()
		query.Set("host", host)
		target.RawQuery = query.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return nil, err
		}
		if r.token != "" {
			req.Header.Set("Authorization", "Bearer "+r.token)
		}
		resp, err := r.client.Do(req)
		if err != nil {
			hadError = true
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || len(raw) > 1<<20 {
			hadError = true
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var result DNSResult
		if err := decoder.Decode(&result); err != nil || normalizeDomain(result.Host) != normalizeDomain(host) {
			hadError = true
			continue
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			hadError = true
			continue
		}
		if len(result.IPs) > 16 {
			result.IPs = result.IPs[:16]
		}
		if len(result.CNAMEs) > 16 {
			result.CNAMEs = result.CNAMEs[:16]
		}
		results = append(results, result)
	}
	if hadError {
		return results, errors.New("DNS provider partially failed")
	}
	return results, nil
}

func NewNetResolver(resolver *net.Resolver, timeout time.Duration) *NetResolver {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 5 * time.Second
	}
	return &NetResolver{resolver: resolver, timeout: timeout}
}

func (r *NetResolver) Resolve(ctx context.Context, hosts []string, concurrency int, gate operationGate) ([]DNSResult, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 50 {
		concurrency = 50
	}
	if len(hosts) > 500 {
		hosts = hosts[:500]
	}
	type indexed struct {
		index  int
		result DNSResult
		err    error
	}
	sem := make(chan struct{}, concurrency)
	results := make(chan indexed, len(hosts))
	var wg sync.WaitGroup
	for index, host := range hosts {
		index, host := index, host
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := gate.Wait(ctx); err != nil {
				results <- indexed{index: index, err: err}
				return
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results <- indexed{index: index, err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			lookupCtx, cancel := context.WithTimeout(ctx, r.timeout)
			defer cancel()
			addresses, ipErr := r.resolver.LookupIPAddr(lookupCtx, host)
			cname, cnameErr := r.resolver.LookupCNAME(lookupCtx, host)
			item := DNSResult{Host: host, IPs: []string{}, CNAMEs: []string{}}
			for _, address := range addresses {
				item.IPs = append(item.IPs, address.IP.String())
			}
			if normalized := normalizeDomain(cname); normalized != "" && normalized != host {
				item.CNAMEs = append(item.CNAMEs, normalized)
			}
			if ipErr != nil && cnameErr != nil {
				results <- indexed{index: index, result: item, err: errors.New("dns lookup failed")}
				return
			}
			results <- indexed{index: index, result: item}
		}()
	}
	wg.Wait()
	close(results)
	ordered := make([]indexed, 0, len(hosts))
	var hadError bool
	for result := range results {
		ordered = append(ordered, result)
		hadError = hadError || result.err != nil
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].index < ordered[j].index })
	out := make([]DNSResult, 0, len(ordered))
	for _, item := range ordered {
		out = append(out, item.result)
	}
	if hadError {
		return out, errors.New("dns resolution partially failed")
	}
	return out, nil
}
