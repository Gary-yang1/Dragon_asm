package discovery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeHTTPClient struct {
	do func(req *http.Request) (*http.Response, error)
}

func (f fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return f.do(req)
}

func TestHTTPEngineAdapterDispatch(t *testing.T) {
	var seenIDKey string
	var seenAuth string
	var seenBody dispatchRequest
	client := fakeHTTPClient{do: func(r *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/scan", r.URL.Path)
		seenIDKey = r.Header.Get("Idempotency-Key")
		seenAuth = r.Header.Get("Authorization")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&seenBody))
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(strings.NewReader(`{"engine_job_id":"engine-1"}`)),
		}, nil
	}}

	adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "token-1", client)
	require.NoError(t, err)
	engineJobID, err := adapter.Dispatch(context.Background(), ScanJob{
		RunID:       42,
		ProjectID:   7,
		ScopeID:     11,
		JobType:     TaskTypeDNS,
		Targets:     []Target{{Type: TargetTypeDomain, Value: "example.com"}},
		RateLimit:   10,
		Concurrency: 2,
		Timeout:     30 * time.Second,
		CallbackURL: "https://asm.example.com/api/v1/discovery/callback?project_id=7&run_id=42",
		Options:     map[string]any{"profile": "resolve", "record_types": []string{"A"}, "max_results": 100},
	})
	require.NoError(t, err)

	assert.Equal(t, "engine-1", engineJobID)
	assert.Equal(t, "42", seenIDKey)
	assert.Equal(t, "Bearer token-1", seenAuth)
	assert.Equal(t, uint64(42), seenBody.RunID)
	assert.Equal(t, uint64(7), seenBody.ProjectID)
	assert.Equal(t, uint64(11), seenBody.ScopeID)
	assert.Equal(t, engineSchemaVersion, seenBody.SchemaVersion)
	assert.Equal(t, TaskTypeDNS, seenBody.JobType)
	assert.Equal(t, 30, seenBody.TimeoutSeconds)
	assert.Equal(t, []Target{{Type: TargetTypeDomain, Value: "example.com"}}, seenBody.Targets)
}

func TestHTTPEngineAdapterDispatchRejectsNonAccepted(t *testing.T) {
	client := fakeHTTPClient{do: func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
		}, nil
	}}

	adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "token", client)
	require.NoError(t, err)
	_, err = adapter.Dispatch(context.Background(), ScanJob{
		RunID: 42, ProjectID: 7, ScopeID: 11, JobType: TaskTypeDNS,
		Targets: []Target{{Type: TargetTypeDomain, Value: "example.com"}}, CallbackURL: "https://asm.example.com/callback",
	})
	assert.ErrorIs(t, err, ErrEngineDispatch)
}

func TestHTTPEngineAdapterCancel(t *testing.T) {
	var seenPath string
	client := fakeHTTPClient{do: func(r *http.Request) (*http.Response, error) {
		seenPath = r.URL.EscapedPath()
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader(``)),
		}, nil
	}}

	adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "token", client)
	require.NoError(t, err)
	require.NoError(t, adapter.Cancel(context.Background(), "engine/job 1"))
	assert.Equal(t, "/scan/engine%2Fjob%201/cancel", seenPath)
}

func TestHTTPEngineAdapterStatus(t *testing.T) {
	var seenPath string
	client := fakeHTTPClient{do: func(r *http.Request) (*http.Response, error) {
		seenPath = r.URL.EscapedPath()
		require.Equal(t, http.MethodGet, r.Method)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"status":"success","result_count":7}`)),
		}, nil
	}}

	adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "token", client)
	require.NoError(t, err)
	status, err := adapter.Status(context.Background(), "engine/job 1")
	require.NoError(t, err)
	assert.Equal(t, "/scan/engine%2Fjob%201", seenPath)
	assert.Equal(t, EngineJobStatusSuccess, status.Status)
	assert.Equal(t, uint64(7), status.ResultCount)
}

func TestHTTPEngineAdapterRequiresTokenAndUsesBoundedDefaultClient(t *testing.T) {
	_, err := NewHTTPEngineAdapter("https://engine.example.com", "", nil)
	assert.ErrorIs(t, err, ErrEngineNotConfigured)

	adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "token", nil)
	require.NoError(t, err)
	client, ok := adapter.client.(*http.Client)
	require.True(t, ok)
	assert.Equal(t, engineHTTPTimeout, client.Timeout)
}

func TestHTTPEngineAdapterCheckManagementStatusUsesAuthenticatedGET(t *testing.T) {
	client := fakeHTTPClient{do: func(r *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, engineManagementPath, r.URL.Path)
		require.Equal(t, "Bearer management-token", r.Header.Get("Authorization"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{
				"status":"ready","engine_id":"baiyan-primary",
				"capabilities":["dns","passive_intel"],
				"providers":[{"key":"fofa","name":"FOFA","configured":true,
					"credentials":[{"key":"key","configured":true,"masked_value":"••••••••abcd"}]}]
			}`)),
		}, nil
	}}
	adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "management-token", client)
	require.NoError(t, err)

	status, err := adapter.CheckManagementStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "baiyan-primary", status.EngineID)
	require.Len(t, status.Providers, 1)
	assert.Equal(t, "••••••••abcd", status.Providers[0].Credentials[0].MaskedValue)
}

func TestHTTPEngineAdapterCheckManagementStatusRejectsInvalidResponses(t *testing.T) {
	tooManyCapabilities, err := json.Marshal(PassiveEngineManagementStatus{
		Status: "ready", EngineID: "baiyan", Capabilities: make([]string, 65),
	})
	require.NoError(t, err)
	tooManyProviders, err := json.Marshal(PassiveEngineManagementStatus{
		Status: "ready", EngineID: "baiyan", Providers: make([]PassiveEngineProviderStatus, 33),
	})
	require.NoError(t, err)
	tooManyCredentials, err := json.Marshal(PassiveEngineManagementStatus{
		Status: "ready", EngineID: "baiyan", Providers: []PassiveEngineProviderStatus{{
			Key: "fofa", Name: "FOFA", Credentials: make([]PassiveEngineCredentialStatus, 17),
		}},
	})
	require.NoError(t, err)

	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "non success", statusCode: http.StatusUnauthorized, body: `{}`},
		{name: "not ready", statusCode: http.StatusOK, body: `{"status":"degraded","engine_id":"baiyan","providers":[]}`},
		{name: "empty engine id", statusCode: http.StatusOK, body: `{"status":"ready","engine_id":"","providers":[]}`},
		{name: "unknown field", statusCode: http.StatusOK, body: `{"status":"ready","engine_id":"baiyan","providers":[],"token":"raw"}`},
		{name: "trailing json", statusCode: http.StatusOK, body: `{"status":"ready","engine_id":"baiyan","providers":[]} {}`},
		{name: "oversized body", statusCode: http.StatusOK, body: `{"status":"ready","engine_id":"baiyan","providers":[],"padding":"` + strings.Repeat("x", engineMaxResponseBody) + `"}`},
		{name: "too many capabilities", statusCode: http.StatusOK, body: string(tooManyCapabilities)},
		{name: "too many providers", statusCode: http.StatusOK, body: string(tooManyProviders)},
		{name: "too many credentials", statusCode: http.StatusOK, body: string(tooManyCredentials)},
		{name: "missing provider key", statusCode: http.StatusOK, body: `{"status":"ready","engine_id":"baiyan","providers":[{"key":"","name":"FOFA","credentials":[]}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tt.statusCode, Body: io.NopCloser(strings.NewReader(tt.body))}, nil
			}}
			adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "token", client)
			require.NoError(t, err)
			_, err = adapter.CheckManagementStatus(context.Background())
			assert.ErrorIs(t, err, ErrEngineStatus)
		})
	}
}

func TestHTTPEngineAdapterRejectsInvalidStatusAndOversizedResponse(t *testing.T) {
	tests := []string{
		`{"status":"unknown","progress":1,"result_count":0,"error_summary":""}`,
		`{"status":"running","progress":101,"result_count":0,"error_summary":""}`,
		`{"status":"running","progress":1,"result_count":0,"error_summary":"","unknown":true}`,
		`{"status":"running","progress":1,"result_count":0,"error_summary":"` + strings.Repeat("x", engineMaxResponseBody) + `"}`,
	}
	for _, body := range tests {
		client := fakeHTTPClient{do: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		}}
		adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "token", client)
		require.NoError(t, err)
		_, err = adapter.Status(context.Background(), "job-1")
		assert.Error(t, err)
	}
}

func TestBlueprintMetadataStaysInASMForPassiveAndDNSDispatch(t *testing.T) {
	for _, kind := range []string{TaskTypePassiveIntel, TaskTypeDNS} {
		t.Run(kind, func(t *testing.T) {
			options := map[string]any{"profile": "subdomain_passive", "sources": []string{"auto"}, "max_results": 1000, "blueprint_key": "domain_asset_inventory", "blueprint_version": "1.0.0", "blueprint_scope_id": 6, "blueprint_step_key": "passive_intel", "depends_on": []string{}}
			if kind == TaskTypeDNS {
				options["profile"] = "resolve"
				delete(options, "sources")
				options["record_types"] = []string{"A", "AAAA", "CNAME"}
				options["depends_on"] = []string{"passive_intel"}
			}
			client := fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
				var body dispatchRequest
				require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
				for _, key := range []string{"blueprint_key", "blueprint_version", "blueprint_scope_id", "blueprint_step_key", "depends_on"} {
					assert.NotContains(t, body.Options, key)
				}
				assert.Equal(t, options["profile"], body.Options["profile"])
				assert.Equal(t, float64(1000), body.Options["max_results"])
				return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"engine_job_id":"job-fixture"}`))}, nil
			}}
			adapter, err := NewHTTPEngineAdapter("https://engine.example.test", "test", client)
			require.NoError(t, err)
			_, err = adapter.Dispatch(context.Background(), ScanJob{RunID: 13, ProjectID: 6, ScopeID: 6, JobType: kind, Targets: []Target{{Type: TargetTypeDomain, Value: "example.com"}}, CallbackURL: "https://asm.example.test/api/v1/discovery/callback?project_id=6&run_id=13", Options: options})
			require.NoError(t, err)
			assert.Contains(t, options, "blueprint_key")
			assert.Contains(t, options, "depends_on")
		})
	}
	assert.Contains(t, engineExecutionOptions(map[string]any{"unsafe_unknown": true}), "unsafe_unknown")
}
func TestDispatchRetainsOnlyKnownEngineErrorCode(t *testing.T) {
	client := fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 422, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"INVALID_PROFILE","message":"secret-must-not-leak"}}`))}, nil
	}}
	adapter, err := NewHTTPEngineAdapter("https://engine.example.test", "test", client)
	require.NoError(t, err)
	_, err = adapter.Dispatch(context.Background(), ScanJob{RunID: 1, ProjectID: 1, ScopeID: 1, JobType: TaskTypeDNS, Targets: []Target{{Type: TargetTypeDomain, Value: "example.com"}}, CallbackURL: "https://asm.example.test/callback"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "INVALID_PROFILE")
	assert.NotContains(t, err.Error(), "secret-must-not-leak")
}
