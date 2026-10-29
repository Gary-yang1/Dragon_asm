package capability

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFOFAPassiveProviderDiscoversNormalizedHosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s", r.Method)
		}
		query := r.URL.Query()
		if query.Get("email") != "user@example.com" || query.Get("key") != "secret-key" {
			t.Fatal("FOFA credentials missing")
		}
		decoded, err := base64.StdEncoding.DecodeString(query.Get("qbase64"))
		if err != nil || string(decoded) != `domain="example.com"` {
			t.Fatalf("query = %q, err = %v", decoded, err)
		}
		if query.Get("fields") != fofaFields || query.Get("size") != "10" || query.Get("page") != "1" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		// host,domain,ip,port,protocol,title,server
		_, _ = w.Write([]byte(`{"error":false,"results":[` +
			`["https://www.example.com:443/","www.example.com","192.0.2.1","443","https","Example \u0007Home\n","nginx"],` +
			`["api.example.com:8443","","192.0.2.2","8443","http","",""],` +
			`["https://www.example.com","www.example.com","192.0.2.1","443","https","Example Home","nginx"],` +
			`["ssh.example.com:22","example.com","192.0.2.3","22","ssh","",""]]}`))
	}))
	defer server.Close()

	provider, err := NewFOFAPassiveProvider("user@example.com", "secret-key", server.URL, server.Client(), 10)
	if err != nil {
		t.Fatal(err)
	}
	hosts, sites, err := provider.DiscoverSites(context.Background(), "Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(hosts, ",") != "www.example.com,api.example.com,example.com,ssh.example.com" {
		t.Fatalf("hosts = %#v", hosts)
	}
	// Only HTTP(S) rows are websites; the SSH row stays host evidence.
	if len(sites) != 3 || sites[0] != (SiteSnapshot{Host: "www.example.com", Scheme: "https", Port: 443, Title: "Example \u0007Home\n", Server: "nginx"}) ||
		sites[1].siteURL() != "http://api.example.com:8443" {
		t.Fatalf("sites = %#v", sites)
	}
	if hosts, err := provider.Discover(context.Background(), "example.com"); err != nil || len(hosts) != 4 {
		t.Fatalf("Discover = %v, %v", hosts, err)
	}
}

func TestFOFAPassiveProviderDoesNotFollowRedirectsOrLeakErrors(t *testing.T) {
	var redirected bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	provider, err := NewFOFAPassiveProvider("user@example.com", "secret-key", source.URL, source.Client(), 10)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Discover(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected redirect to fail")
	}
	if redirected {
		t.Fatal("FOFA client followed redirect")
	}
	if strings.Contains(err.Error(), "user@example.com") || strings.Contains(err.Error(), "secret-key") {
		t.Fatalf("credential leaked in error: %v", err)
	}
}

func TestFOFAPassiveProviderRejectsInsecureRemoteEndpoint(t *testing.T) {
	_, err := NewFOFAPassiveProvider("user@example.com", "secret-key", "http://example.com/search", nil, 10)
	if err == nil {
		t.Fatal("expected insecure remote endpoint rejection")
	}
}

func TestNormalizeFOFAHost(t *testing.T) {
	tests := map[string]string{
		"https://WWW.Example.com:443/path": "www.example.com",
		"api.example.com:8443":             "api.example.com",
		"invalid host":                     "",
	}
	for input, want := range tests {
		t.Run(url.QueryEscape(input), func(t *testing.T) {
			if got := normalizeFOFAHost(input); got != want {
				t.Fatalf("normalizeFOFAHost(%q) = %q, want %q", input, got, want)
			}
		})
	}
}
