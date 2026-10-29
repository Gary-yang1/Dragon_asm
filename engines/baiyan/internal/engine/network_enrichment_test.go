package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"baiyan/internal/networkenrich"
)

type fakeNetworkEnricher struct {
	called int
	err    error
}

func (f *fakeNetworkEnricher) Enrich(_ context.Context, request networkenrich.Request) (networkenrich.Response, error) {
	f.called++
	return networkenrich.Response{SchemaVersion: networkenrich.SchemaVersion, Items: []networkenrich.Result{{Key: request.Items[0].Key, Host: request.Items[0].Host, Status: "partial", ResolvedIPs: []string{}, CNAMEs: []string{}, CDN: networkenrich.Attribution{Status: "unknown"}, Cloud: networkenrich.Attribution{Status: "unknown"}, ObservedAt: "2026-09-16T00:00:00Z", RuleVersion: networkenrich.RuleVersion, ErrorKind: "dns_timeout"}}}, f.err
}

func TestNetworkEnrichmentHTTPAuthenticationAndValidation(t *testing.T) {
	valid := `{"schema_version":"1.0","items":[{"key":"web-1","host":"www.example.com","observed_ips":["203.0.113.2"],"fingerprints":["nginx"]}]}`
	for _, test := range []struct {
		name, method, token, body string
		status                    int
	}{
		{"missing authentication", http.MethodPost, "", valid, 401},
		{"wrong token", http.MethodPost, "wrong", valid, 401},
		{"wrong method", http.MethodGet, "engine-token", valid, 405},
		{"unknown field", http.MethodPost, "engine-token", `{"schema_version":"1.0","items":[{"key":"1","host":"example.com","scan":true}]}`, 400},
		{"second JSON value", http.MethodPost, "engine-token", valid + "{}", 400},
		{"missing items", http.MethodPost, "engine-token", `{"schema_version":"1.0","items":[]}`, 422},
		{"unsafe host", http.MethodPost, "engine-token", `{"schema_version":"1.0","items":[{"key":"1","host":"http://localhost"}]}`, 422},
		{"oversized body", http.MethodPost, "engine-token", strings.Repeat(" ", maxNetworkEnrichmentBody+1), 413},
		{"valid partial result", http.MethodPost, "engine-token", valid, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(&panicManagementJobs{}, "engine-token", "https://asm.example.com")
			if err != nil {
				t.Fatal(err)
			}
			enricher := &fakeNetworkEnricher{}
			handler.networkEnricher = enricher
			request := httptest.NewRequest(test.method, "/enrich/network", strings.NewReader(test.body))
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			response := httptest.NewRecorder()
			handler.Routes().ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if test.status != 200 && enricher.called != 0 {
				t.Fatal("invalid request reached enricher")
			}
			if test.status == 405 && response.Header().Get("Allow") != "POST" {
				t.Fatal("missing Allow header")
			}
			if test.status == 200 {
				var value networkenrich.Response
				decoder := json.NewDecoder(bytes.NewReader(response.Body.Bytes()))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&value); err != nil {
					t.Fatal(err)
				}
				if enricher.called != 1 || value.Items[0].Status != "partial" || value.Items[0].Key != "web-1" || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("bad response: %+v", value)
				}
			}
		})
	}
}

func TestNetworkEnrichmentHTTPDoesNotExposeInternalErrors(t *testing.T) {
	handler, _ := NewHandler(&panicManagementJobs{}, "engine-token", "https://asm.example.com")
	handler.networkEnricher = &fakeNetworkEnricher{err: errors.New("sensitive resolver details")}
	request := httptest.NewRequest(http.MethodPost, "/enrich/network", strings.NewReader(`{"schema_version":"1.0","items":[{"key":"1","host":"www.example.com"}]}`))
	request.Header.Set("Authorization", "Bearer engine-token")
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != 503 || strings.Contains(response.Body.String(), "sensitive") {
		t.Fatalf("bad failure response: %d %s", response.Code, response.Body.String())
	}
}

func TestNetworkEnrichmentCapabilityIsAlwaysAdvertisedOnce(t *testing.T) {
	handler, err := NewHandlerWithManagement(&panicManagementJobs{}, "engine-token", "https://asm.example.com", ManagementConfig{EngineID: "baiyan-primary", Capabilities: []string{"dns", networkenrich.Capability}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(handler.management.Capabilities, ",") != "dns,network_enrichment" {
		t.Fatalf("duplicate capability: %v", handler.management.Capabilities)
	}
}
