package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type providerControl struct {
	mu     sync.Mutex
	states map[string]*domainState
}

type domainState struct {
	hold     bool
	fail     bool
	release  chan struct{}
	requests int
}

type controlRequest struct {
	Domain string `json:"domain"`
	Hold   bool   `json:"hold"`
	Fail   bool   `json:"fail"`
}

func newProviderControl() *providerControl {
	return &providerControl{states: make(map[string]*domainState)}
}

func (c *providerControl) configure(domain string, hold, fail bool) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !documentationDomain(domain) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if previous := c.states[domain]; previous != nil && previous.hold {
		close(previous.release)
	}
	state := &domainState{hold: hold, fail: fail}
	if hold {
		state.release = make(chan struct{})
	}
	c.states[domain] = state
	return true
}

func (c *providerControl) release(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.states[domain]
	if state == nil {
		return false
	}
	if state.hold {
		close(state.release)
		state.hold = false
		state.release = nil
	}
	return true
}

func (c *providerControl) beforeRequest(ctx context.Context, domain string) (bool, error) {
	c.mu.Lock()
	state := c.states[domain]
	if state == nil {
		state = &domainState{}
		c.states[domain] = state
	}
	state.requests++
	fail := state.fail
	release := state.release
	hold := state.hold
	c.mu.Unlock()
	if hold {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-release:
		}
	}
	return fail, nil
}

func (c *providerControl) status(domain string) map[string]any {
	domain = strings.ToLower(strings.TrimSpace(domain))
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.states[domain]
	if state == nil {
		return map[string]any{"domain": domain, "requests": 0, "hold": false, "fail": false}
	}
	return map[string]any{"domain": domain, "requests": state.requests, "hold": state.hold, "fail": state.fail}
}

func main() {
	token := os.Getenv("MOCK_PROVIDER_TOKEN")
	control := newProviderControl()
	authorized := func(r *http.Request) bool {
		return token == "" || r.Header.Get("Authorization") == "Bearer "+token
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/subdomains", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
		if !documentationDomain(domain) {
			http.Error(w, "unsupported documentation domain", http.StatusUnprocessableEntity)
			return
		}
		fail, err := control.beforeRequest(r.Context(), domain)
		if err != nil {
			return
		}
		if fail {
			http.Error(w, "injected provider failure", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"subdomains": []string{"api." + domain}})
	})
	mux.HandleFunc("/dns", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
		if !strings.HasPrefix(host, "api.") || !documentationDomain(strings.TrimPrefix(host, "api.")) {
			http.Error(w, "unsupported documentation host", http.StatusUnprocessableEntity)
			return
		}
		writeJSON(w, map[string]any{"host": host, "ips": []string{"192.0.2.10"}, "cnames": []string{}})
	})
	mux.HandleFunc("/control/configure", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) || r.Method != http.MethodPost {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request controlRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || !control.configure(request.Domain, request.Hold, request.Fail) {
			http.Error(w, "invalid control request", http.StatusBadRequest)
			return
		}
		writeJSON(w, control.status(request.Domain))
	})
	mux.HandleFunc("/control/release", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) || r.Method != http.MethodPost {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request controlRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || !control.release(request.Domain) {
			http.Error(w, "invalid control request", http.StatusBadRequest)
			return
		}
		writeJSON(w, control.status(request.Domain))
	})
	mux.HandleFunc("/control/status", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) || r.Method != http.MethodGet {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, control.status(r.URL.Query().Get("domain")))
	})
	server := &http.Server{
		Addr:              envOr("MOCK_PROVIDER_ADDR", "127.0.0.1:19191"),
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func documentationDomain(value string) bool {
	return value == "example.com" || strings.HasSuffix(value, ".example.com")
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
