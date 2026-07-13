package capability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPPassiveProviderDoesNotFollowRedirects(t *testing.T) {
	assertProviderRedirectRejected(t, func(sourceURL string, client *http.Client) error {
		provider, err := NewHTTPPassiveProvider("test", sourceURL, "provider-token", client, 10)
		if err != nil {
			return err
		}
		_, err = provider.Discover(context.Background(), "example.com")
		return err
	})
}

func TestHTTPResolverDoesNotFollowRedirects(t *testing.T) {
	assertProviderRedirectRejected(t, func(sourceURL string, client *http.Client) error {
		resolver, err := NewHTTPResolver(sourceURL, "dns-token", client, 10)
		if err != nil {
			return err
		}
		_, err = resolver.Resolve(context.Background(), []string{"example.com"}, 1, immediateGate{})
		return err
	})
}

type immediateGate struct{}

func (immediateGate) Wait(ctx context.Context) error { return ctx.Err() }

func assertProviderRedirectRejected(t *testing.T, request func(string, *http.Client) error) {
	t.Helper()
	var redirected bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		if r.Header.Get("Authorization") != "" {
			t.Error("provider credential reached redirect destination")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subdomains":[]}`))
	}))
	defer destination.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	if err := request(source.URL, source.Client()); err == nil {
		t.Fatal("expected redirect response to fail provider request")
	}
	if redirected {
		t.Fatal("provider client followed redirect")
	}
}
