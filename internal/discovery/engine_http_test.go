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
		RunID:       "42",
		JobType:     TaskTypeDNS,
		Targets:     []Target{{Type: TargetTypeDomain, Value: "example.com"}},
		RateLimit:   10,
		Concurrency: 2,
		Timeout:     30 * time.Second,
		CallbackURL: "https://asm.example.com/callback",
		Options:     map[string]any{"profile": "standard"},
	})
	require.NoError(t, err)

	assert.Equal(t, "engine-1", engineJobID)
	assert.Equal(t, "42", seenIDKey)
	assert.Equal(t, "Bearer token-1", seenAuth)
	assert.Equal(t, "42", seenBody.RunID)
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

	adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "", client)
	require.NoError(t, err)
	_, err = adapter.Dispatch(context.Background(), ScanJob{
		RunID:   "42",
		JobType: TaskTypeDNS,
		Targets: []Target{{Type: TargetTypeDomain, Value: "example.com"}},
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

	adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "", client)
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

	adapter, err := NewHTTPEngineAdapter("https://engine.example.com", "", client)
	require.NoError(t, err)
	status, err := adapter.Status(context.Background(), "engine/job 1")
	require.NoError(t, err)
	assert.Equal(t, "/scan/engine%2Fjob%201", seenPath)
	assert.Equal(t, EngineJobStatusSuccess, status.Status)
	assert.Equal(t, uint64(7), status.ResultCount)
}
