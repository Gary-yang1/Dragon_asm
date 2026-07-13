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
