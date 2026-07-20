package capability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultFOFAEndpoint = "https://fofa.info/api/v1/search/all"
	maxFOFAResponseSize = 1 << 20
)

// FOFAPassiveProvider adapts FOFA's search API to the passive subdomain
// provider contract. Credentials are never included in returned errors.
type FOFAPassiveProvider struct {
	email    string
	key      string
	endpoint *url.URL
	client   *http.Client
	max      int
}

func NewFOFAPassiveProvider(email, key, endpoint string, client *http.Client, maxResults int) (*FOFAPassiveProvider, error) {
	email = strings.TrimSpace(email)
	key = strings.TrimSpace(key)
	if email == "" || key == "" {
		return nil, errors.New("baiyan FOFA provider: email and key are required")
	}
	if strings.TrimSpace(endpoint) == "" {
		endpoint = defaultFOFAEndpoint
	}
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && !isLoopbackHTTP(parsed)) {
		return nil, errors.New("baiyan FOFA provider: invalid endpoint")
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	client = withoutRedirects(client)
	if maxResults < 1 || maxResults > 1000 {
		maxResults = 1000
	}
	return &FOFAPassiveProvider{email: email, key: key, endpoint: parsed, client: client, max: maxResults}, nil
}

func (p *FOFAPassiveProvider) Name() string { return "fofa" }

func (p *FOFAPassiveProvider) Discover(ctx context.Context, rootDomain string) ([]string, error) {
	root := normalizeDomain(rootDomain)
	if root == "" {
		return nil, errors.New("baiyan FOFA provider: invalid root domain")
	}
	target := *p.endpoint
	query := target.Query()
	query.Set("email", p.email)
	query.Set("key", p.key)
	query.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`domain="%s"`, root))))
	query.Set("size", strconv.Itoa(p.max))
	query.Set("page", "1")
	query.Set("fields", "host,domain")
	target.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, errors.New("baiyan FOFA provider: request creation failed")
	}
	req.Header.Set("User-Agent", "Baiyan-Engine/1.0")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, errors.New("baiyan FOFA provider: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, errors.New("baiyan FOFA provider: non-success response")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFOFAResponseSize+1))
	if err != nil || len(raw) > maxFOFAResponseSize {
		return nil, errors.New("baiyan FOFA provider: response exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var payload struct {
		Error   bool    `json:"error"`
		Results [][]any `json:"results"`
	}
	if err := decoder.Decode(&payload); err != nil {
		return nil, errors.New("baiyan FOFA provider: invalid response")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("baiyan FOFA provider: response contains extra JSON")
	}
	if payload.Error {
		return nil, errors.New("baiyan FOFA provider: upstream rejected query")
	}

	capacity := len(payload.Results)
	if capacity > p.max {
		capacity = p.max
	}
	result := make([]string, 0, capacity)
	seen := make(map[string]struct{})
	for _, row := range payload.Results {
		for _, index := range []int{1, 0} {
			if index >= len(row) {
				continue
			}
			rawHost, ok := row[index].(string)
			if !ok {
				continue
			}
			host := normalizeFOFAHost(rawHost)
			if host == "" {
				continue
			}
			if _, duplicate := seen[host]; duplicate {
				continue
			}
			seen[host] = struct{}{}
			result = append(result, host)
			if len(result) >= p.max {
				return result, nil
			}
		}
	}
	return result, nil
}

func isLoopbackHTTP(endpoint *url.URL) bool {
	if endpoint == nil || endpoint.Scheme != "http" {
		return false
	}
	host := strings.TrimSpace(endpoint.Hostname())
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeFOFAHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return normalizeDomain(parsed.Hostname())
	}
	value = strings.SplitN(value, "/", 2)[0]
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return normalizeDomain(strings.Trim(value, "[]"))
}
