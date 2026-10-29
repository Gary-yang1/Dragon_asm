package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"baiyan/internal/contract"
	"baiyan/internal/job"
)

type panicManagementJobs struct{}

func (*panicManagementJobs) Submit(contract.ScanRequest, string) (job.Record, bool, error) {
	panic("management status must not submit a job")
}

func (*panicManagementJobs) Get(string) (job.Record, error) {
	panic("management status must not read a job")
}

func (*panicManagementJobs) Cancel(string) (job.Record, error) {
	panic("management status must not cancel a job")
}

func managementTestHandler(t *testing.T) *Handler {
	t.Helper()
	handler, err := NewHandlerWithManagement(
		&panicManagementJobs{}, "engine-token", "https://asm.example.com",
		ManagementConfig{
			EngineID:     "baiyan-primary",
			Capabilities: []string{"passive_intel", "dns", "passive_intel"},
			Providers: []ManagementProviderConfig{
				{
					Key: "fofa", Name: "FOFA", Configured: true,
					Credentials: []ManagementCredentialConfig{
						{Key: "key", Kind: CredentialKindSecret, Value: "fake-fofa-key-for-tests-9x7z"},
						{Key: "email", Kind: CredentialKindEmail, Value: "test-user@example.invalid"},
					},
				},
				{
					Key: "passive_http", Name: "Passive HTTP", Configured: false,
					Credentials: []ManagementCredentialConfig{
						{Key: "token", Kind: CredentialKindSecret, Value: ""},
					},
				},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestManagementStatusRequiresBearerAndGET(t *testing.T) {
	handler := managementTestHandler(t)

	request := httptest.NewRequest(http.MethodGet, "/management/status", nil)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"INVALID_AUTH"`) {
		t.Fatalf("missing bearer token was not rejected: code=%d body=%s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/management/status", nil)
	request.Header.Set("Authorization", "Bearer engine-token")
	response = httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet ||
		!strings.Contains(response.Body.String(), `"code":"METHOD_NOT_ALLOWED"`) {
		t.Fatalf("non-GET method was not rejected: code=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestManagementStatusReturnsOnlyMaskedSnapshot(t *testing.T) {
	handler := managementTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/management/status", nil)
	request.Header.Set("Authorization", "Bearer engine-token")
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: code=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("management response can be cached: %q", response.Header().Get("Cache-Control"))
	}
	raw := response.Body.String()
	for _, secret := range []string{"engine-token", "test-user@example.invalid", "fake-fofa-key-for-tests-9x7z"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("raw credential leaked in response: %q", secret)
		}
	}

	var status managementStatus
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Status != managementStatusReady || status.EngineID != "baiyan-primary" {
		t.Fatalf("unexpected engine status: %+v", status)
	}
	if got := strings.Join(status.Capabilities, ","); got != "dns,network_enrichment,passive_intel" {
		t.Fatalf("capabilities are not stable and deduplicated: %q", got)
	}
	if len(status.Providers) != 2 || status.Providers[0].Key != "fofa" || !status.Providers[0].Configured {
		t.Fatalf("unexpected provider summary: %+v", status.Providers)
	}
	fofaCredentials := status.Providers[0].Credentials
	if len(fofaCredentials) != 2 || fofaCredentials[0].Key != "email" ||
		fofaCredentials[0].MaskedValue != "t********r@example.invalid" ||
		fofaCredentials[1].Key != "key" || fofaCredentials[1].MaskedValue != fixedSecretMask+"9x7z" {
		t.Fatalf("FOFA credentials were not masked as expected: %+v", fofaCredentials)
	}
	missing := status.Providers[1]
	if missing.Key != "passive_http" || missing.Configured || len(missing.Credentials) != 1 ||
		missing.Credentials[0].Configured || missing.Credentials[0].MaskedValue != "" {
		t.Fatalf("unconfigured credential summary is incorrect: %+v", missing)
	}
}

func TestManagementCredentialMaskingDoesNotRevealShortSecretOrLength(t *testing.T) {
	short := maskManagementCredential("token", CredentialKindSecret, "abc")
	long := maskManagementCredential("token", CredentialKindSecret, "abcd1234")
	if short.MaskedValue != fixedSecretMask || strings.Contains(short.MaskedValue, "abc") {
		t.Fatalf("short secret leaked: %+v", short)
	}
	if long.MaskedValue != fixedSecretMask+"1234" {
		t.Fatalf("long secret suffix was not masked consistently: %+v", long)
	}
	if maskManagementCredential("token", CredentialKindSecret, "  ").MaskedValue != "" {
		t.Fatal("unconfigured secret should have an empty masked value")
	}
}
