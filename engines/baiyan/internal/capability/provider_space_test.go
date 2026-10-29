package capability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSpaceProvidersParseAndFilterDomainResults(t *testing.T) {
	for _, name := range []string{"quake", "hunter"} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if name == "quake" {
					if r.Header.Get("X-QuakeToken") != "credential" {
						t.Error("missing Quake credential")
					}
					w.Write([]byte(`{"code":"0","data":[{"domain":"api.example.com"},{"domain":"outside.test"}]}`))
				} else {
					if r.URL.Query().Get("api-key") != "credential" {
						t.Error("missing Hunter credential")
					}
					w.Write([]byte(`{"code":200,"data":{"total":2,"arr":[{"domain":"api.example.com"},{"domain":"outside.test"}]}}`))
				}
			}))
			defer server.Close()
			p := NewSpaceProvider(name, "credential", server.Client(), 1000)
			p.endpoint = server.URL
			values, err := p.Discover(context.Background(), "example.com")
			if err != nil || len(values) != 1 || values[0] != "api.example.com" {
				t.Fatalf("%v %v", values, err)
			}
		})
	}
}
func TestSpaceErrorsNeverExposeCredentialsOrResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403); w.Write([]byte("secret-value")) }))
	defer s.Close()
	p := NewSpaceProvider("hunter", "secret-value", s.Client(), 100)
	p.endpoint = s.URL
	_, err := p.Discover(context.Background(), "example.com")
	if err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("unsafe error %v", err)
	}
}
