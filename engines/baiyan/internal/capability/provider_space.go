package capability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SpaceProvider adapts the existing Quake/Hunter query contracts. Credentials
// and upstream response text never appear in errors or stage messages.
type SpaceProvider struct {
	gate                operationGate
	name, key, endpoint string
	client              *http.Client
	max                 int
}

func NewSpaceProvider(name, key string, client *http.Client, max int) *SpaceProvider {
	endpoint := "https://quake.360.net/api/v3/search/quake_service"
	if name == "hunter" {
		endpoint = "https://hunter.qianxin.com/openApi/search"
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	if max < 1 || max > 1000 {
		max = 1000
	}
	return &SpaceProvider{name: name, key: key, endpoint: endpoint, client: withoutRedirects(client), max: max}
}
func (p *SpaceProvider) WithGate(gate operationGate) PassiveProvider {
	copy := *p
	copy.gate = gate
	return &copy
}

func (p *SpaceProvider) Name() string { return p.name }
func (p *SpaceProvider) Discover(ctx context.Context, root string) ([]string, error) {
	var result []string
	err := p.DiscoverStream(ctx, root, func(v []string) error { result = append(result, v...); return nil })
	return result, err
}
func (p *SpaceProvider) DiscoverStream(ctx context.Context, root string, emit func([]string) error) error {
	root = normalizeDomain(root)
	if root == "" || p.key == "" {
		return errors.New("provider configuration invalid")
	}
	for offset := 0; offset < p.max; offset += 100 {
		if offset > 0 {
			if p.gate != nil {
				if err := p.gate.Wait(ctx); err != nil {
					return err
				}
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		size := min(100, p.max-offset)
		var req *http.Request
		var err error
		if p.name == "quake" {
			body, _ := json.Marshal(map[string]any{"query": fmt.Sprintf(`domain="%s"`, root), "start": offset, "size": size})
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
			if err == nil {
				req.Header.Set("X-QuakeToken", p.key)
				req.Header.Set("Content-Type", "application/json")
			}
		} else {
			endpoint, _ := url.Parse(p.endpoint)
			q := endpoint.Query()
			q.Set("api-key", p.key)
			q.Set("search", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`domain.suffix="%s"`, root))))
			q.Set("page", strconv.Itoa(offset/100+1))
			q.Set("page_size", "100")
			q.Set("is_web", "1")
			endpoint.RawQuery = q.Encode()
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		}
		if err != nil {
			return errors.New("provider request invalid")
		}
		resp, err := p.client.Do(req)
		if err != nil {
			return errors.New("provider request failed")
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
		resp.Body.Close()
		if readErr != nil || len(raw) > 4<<20 || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return errors.New("provider response unavailable")
		}
		var envelope struct {
			Code json.RawMessage `json:"code"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &envelope) != nil {
			return errors.New("provider response invalid")
		}
		code := strings.Trim(string(envelope.Code), `" `)
		if code != "200" && !(p.name == "quake" && code == "0") {
			return errors.New("provider query rejected")
		}
		type entry struct {
			Domain string `json:"domain"`
		}
		var rows []entry
		total := p.max
		if p.name == "quake" {
			if json.Unmarshal(envelope.Data, &rows) != nil {
				var nested struct {
					Arr  []entry `json:"arr"`
					Data []entry `json:"data"`
				}
				if json.Unmarshal(envelope.Data, &nested) != nil {
					return errors.New("provider data invalid")
				}
				rows = nested.Arr
				if rows == nil {
					rows = nested.Data
				}
			}
		} else {
			var nested struct {
				Arr   []entry `json:"arr"`
				Total int     `json:"total"`
			}
			if json.Unmarshal(envelope.Data, &nested) != nil {
				return errors.New("provider data invalid")
			}
			rows = nested.Arr
			total = nested.Total
		}
		found := []string{}
		for i, row := range rows {
			if i >= size {
				break
			}
			host := normalizeFOFAHost(row.Domain)
			if host != "" && withinRoot(host, root) {
				found = append(found, host)
			}
		}
		if err := emit(found); err != nil {
			return err
		}
		if len(rows) < 100 || offset+100 >= total {
			return nil
		}
	}
	return nil
}
