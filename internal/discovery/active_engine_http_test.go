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

const (
	activeAPITestAccessKey = "asm-baiyan"
	activeAPITestSecret    = "0123456789abcdef0123456789abcdef"
	activeAPITestNonce     = "nonce-000000001"
)

var activeAPITestTime = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

func newTestActiveAPIAdapter(t *testing.T, client HTTPClient) *ActiveAPIEngineAdapter {
	t.Helper()
	adapter, err := NewActiveAPIEngineAdapter(
		"https://active.example.com",
		activeAPITestAccessKey,
		activeAPITestSecret,
		map[uint64]int{7: 101},
		client,
	)
	require.NoError(t, err)
	adapter.now = func() time.Time { return activeAPITestTime }
	adapter.nonce = func() (string, error) { return activeAPITestNonce, nil }
	return adapter
}

func TestActiveAPISignatureMatchesNodeVector(t *testing.T) {
	body := []byte(`{"ports":"80,443","targets":["203.0.113.10"]}`)
	signature := activeAPISignature(
		activeAPITestSecret,
		http.MethodPost,
		activeAPIPortScanPath,
		"1785153600",
		activeAPITestNonce,
		body,
	)

	assert.Equal(t, "52e3761ab00c93193984e39b8d70e79f6b3becaaebded59cb7357f4ead3316e6", signature)
	assert.NotEqual(t, signature, activeAPISignature(
		activeAPITestSecret,
		http.MethodPost,
		activeAPIPortScanPath,
		"1785153600",
		activeAPITestNonce,
		[]byte(`{"ports":"1-65535","targets":["10.0.0.1"]}`),
	))
}

func TestActiveAPIEngineAdapterDispatchesPortProbe(t *testing.T) {
	var request activeAPIPortScanRequest
	client := fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodPost, req.Method)
		require.Equal(t, activeAPIPortScanPath, req.URL.Path)
		require.Equal(t, activeAPITestAccessKey, req.Header.Get("X-Access-Key"))
		require.Equal(t, "1785153600", req.Header.Get("X-Timestamp"))
		require.Equal(t, activeAPITestNonce, req.Header.Get("X-Nonce"))

		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &request))
		assert.Equal(t, activeAPISignature(
			activeAPITestSecret,
			http.MethodPost,
			activeAPIPortScanPath,
			"1785153600",
			activeAPITestNonce,
			body,
		), req.Header.Get("X-Signature"))
		assert.Empty(t, req.Header.Get("Authorization"))

		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":200,"msg":"ok","data":{"taskid":"active-port-1","total_targets":2,"total_pages":1,"page_size":10}}`,
			)),
		}, nil
	}}

	adapter := newTestActiveAPIAdapter(t, client)
	taskID, err := adapter.Dispatch(context.Background(), ScanJob{
		RunID:     42,
		ProjectID: 7,
		ScopeID:   11,
		JobType:   TaskTypePortProbe,
		Targets: []Target{
			{Type: TargetTypeIP, Value: "203.0.113.10"},
			{Type: TargetTypeIP, Value: "203.0.113.11"},
		},
		Options: map[string]any{
			"ports":   "22,80,443,8000-8002",
			"node_id": "node-eu-1",
		},
	})
	require.NoError(t, err)

	assert.Equal(t, "active-port-1", taskID)
	assert.Equal(t, 101, request.ProjectID)
	assert.Equal(t, "asm:7:42", request.RequestID)
	assert.Equal(t, "ASM-port_probe-42", request.TaskName)
	assert.Equal(t, "node-eu-1", request.NodeID)
	assert.Equal(t, []string{"203.0.113.10", "203.0.113.11"}, request.Targets)
	assert.Equal(t, "22,80,443,8000-8002", request.Ports)
}

func TestActiveAPIEngineAdapterDispatchesWebProbeWithoutPOC(t *testing.T) {
	var request activeAPIWebScanRequest
	client := fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		require.Equal(t, activeAPIWebScanPath, req.URL.Path)
		require.NoError(t, json.NewDecoder(req.Body).Decode(&request))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":200,"msg":"ok","data":{"taskid":"active-web-1","total_targets":1,"total_pages":1,"page_size":10}}`,
			)),
		}, nil
	}}

	adapter := newTestActiveAPIAdapter(t, client)
	taskID, err := adapter.Dispatch(context.Background(), ScanJob{
		RunID:     43,
		ProjectID: 7,
		ScopeID:   11,
		JobType:   TaskTypeWebProbe,
		Targets:   []Target{{Type: TargetTypeURL, Value: "https://example.com:8443/health"}},
		// A template cannot override the enforced read-only mode.
		Options: map[string]any{"nopoc": false},
	})
	require.NoError(t, err)

	assert.Equal(t, "active-web-1", taskID)
	assert.Equal(t, "asm:7:43", request.RequestID)
	assert.True(t, request.NoPOC)
	assert.Equal(t, []string{"https://example.com:8443/health"}, request.URLs)
}

func TestActiveAPIEngineAdapterDispatchesFingerprintAsReadOnlyWebScan(t *testing.T) {
	var request activeAPIWebScanRequest
	client := fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		require.Equal(t, activeAPIWebScanPath, req.URL.Path)
		require.NoError(t, json.NewDecoder(req.Body).Decode(&request))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":200,"msg":"ok","data":{"taskid":"active-fingerprint-1","total_targets":1,"total_pages":1,"page_size":10}}`,
			)),
		}, nil
	}}

	adapter := newTestActiveAPIAdapter(t, client)
	taskID, err := adapter.Dispatch(context.Background(), ScanJob{
		RunID:     44,
		ProjectID: 7,
		ScopeID:   11,
		JobType:   TaskTypeFingerprint,
		Targets:   []Target{{Type: TargetTypeURL, Value: "https://example.com"}},
	})
	require.NoError(t, err)

	assert.Equal(t, "active-fingerprint-1", taskID)
	assert.Equal(t, "asm:7:44", request.RequestID)
	assert.Equal(t, "ASM-fingerprint-44", request.TaskName)
	assert.True(t, request.NoPOC)
	assert.Equal(t, []string{"https://example.com"}, request.URLs)
}

func TestActiveAPIEngineAdapterRejectsUnsafeOrUnmappableJobs(t *testing.T) {
	adapter := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
		t.Fatal("rejected jobs must not make an HTTP request")
		return nil, nil
	}})

	validPortJob := ScanJob{
		RunID:     42,
		ProjectID: 7,
		ScopeID:   11,
		JobType:   TaskTypePortProbe,
		Targets:   []Target{{Type: TargetTypeIP, Value: "203.0.113.10"}},
		Options:   map[string]any{"ports": "80,443"},
	}

	tests := []struct {
		name string
		edit func(*ScanJob)
	}{
		{name: "unmapped project", edit: func(job *ScanJob) { job.ProjectID = 8 }},
		{name: "missing scope", edit: func(job *ScanJob) { job.ScopeID = 0 }},
		{name: "unsupported task", edit: func(job *ScanJob) { job.JobType = TaskTypeDirScan }},
		{name: "port target must be an IP", edit: func(job *ScanJob) {
			job.Targets = []Target{{Type: TargetTypeCIDR, Value: "203.0.113.0/24"}}
		}},
		{name: "all ports is prohibited", edit: func(job *ScanJob) { job.Options["ports"] = "all" }},
		{name: "too many ports", edit: func(job *ScanJob) { job.Options["ports"] = "1-1001" }},
		{name: "ports must match node grammar", edit: func(job *ScanJob) { job.Options["ports"] = "+80" }},
		{name: "node id contains whitespace", edit: func(job *ScanJob) { job.Options["node_id"] = "node one" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			job := validPortJob
			job.Targets = append([]Target(nil), validPortJob.Targets...)
			job.Options = map[string]any{"ports": validPortJob.Options["ports"]}
			tc.edit(&job)
			_, err := adapter.Dispatch(context.Background(), job)
			assert.ErrorIs(t, err, ErrEngineJobRejected)
		})
	}
}

func TestActiveAPIEngineAdapterStatusNormalizesNodeResponse(t *testing.T) {
	client := fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodPost, req.Method)
		require.Equal(t, activeAPIStatusPath, req.URL.Path)

		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"taskid":"active-web-1"}`, string(body))
		assert.Equal(t, activeAPISignature(
			activeAPITestSecret,
			http.MethodPost,
			activeAPIStatusPath,
			"1785153600",
			activeAPITestNonce,
			body,
		), req.Header.Get("X-Signature"))

		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":200,"msg":"ok","data":{"taskid":"active-web-1","scan_type":"webscan","status":"waiting","progress":"45%","total_pages":"2","total_targets":"12","finished_targets":5,"create_time":"1785153600"}}`,
			)),
		}, nil
	}}

	adapter := newTestActiveAPIAdapter(t, client)
	status, err := adapter.Status(context.Background(), "active-web-1")
	require.NoError(t, err)

	assert.Equal(t, EngineJobStatusRunning, status.Status)
	assert.Equal(t, 45, status.Progress)
	assert.Zero(t, status.ResultCount)
}

func TestActiveAPIEngineAdapterFetchesPortResultPage(t *testing.T) {
	client := fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodPost, req.Method)
		require.Equal(t, activeAPIPortResultPath, req.URL.Path)
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"taskid":"active-port-1","page":1,"pagesize":50}`, string(body))
		assert.Equal(t, activeAPISignature(
			activeAPITestSecret,
			http.MethodPost,
			activeAPIPortResultPath,
			"1785153600",
			activeAPITestNonce,
			body,
		), req.Header.Get("X-Signature"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":200,"msg":"ok","data":{"taskid":"active-port-1","total_targets":2,` +
					`"finished_targets":2,"visible_results":2,"page":1,"page_size":50,` +
					`"results":[{"target":"203.0.113.10","ports":"80,443"},` +
					`{"target":"203.0.113.11","ports":""}]}}`,
			)),
		}, nil
	}}

	page, err := newTestActiveAPIAdapter(t, client).FetchResultPage(
		context.Background(),
		"active-port-1",
		TaskTypePortProbe,
		1,
		activeAPIResultPageSize,
	)
	require.NoError(t, err)
	assert.Equal(t, 2, page.TotalTargets)
	assert.Equal(t, 2, page.FinishedTargets)
	assert.Equal(t, []EnginePortResult{
		{Target: "203.0.113.10", Ports: "80,443"},
		{Target: "203.0.113.11", Ports: ""},
	}, page.PortResults)
	assert.Empty(t, page.WebResults)
}

func TestActiveAPIEngineAdapterFetchesWebResultWithoutRetainingPOCEvidence(t *testing.T) {
	client := fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		require.Equal(t, activeAPIWebResultPath, req.URL.Path)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":200,"msg":"ok","data":{"taskid":"active-web-1","total_targets":1,` +
					`"finished_targets":1,"page":1,"page_size":50,"results":[{` +
					`"target":"https://example.com","port":443,` +
					`"finger_results":[{"name":"nginx","status_code":"200","title":"Example"}],` +
					`"poc_results":[{"req_json":"Authorization: Bearer must-not-persist",` +
					`"resp_json":"Set-Cookie: must-not-persist"}],"is_vul":true}]}}`,
			)),
		}, nil
	}}

	page, err := newTestActiveAPIAdapter(t, client).FetchResultPage(
		context.Background(),
		"active-web-1",
		TaskTypeWebProbe,
		1,
		activeAPIResultPageSize,
	)
	require.NoError(t, err)
	require.Len(t, page.WebResults, 1)
	assert.Equal(t, "https://example.com", page.WebResults[0].Target)
	assert.Equal(t, []EngineWebFingerprint{{
		Name: "nginx", StatusCode: "200", Title: "Example",
	}}, page.WebResults[0].Fingerprints)

	raw, err := json.Marshal(page)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "must-not-persist")
	assert.NotContains(t, string(raw), "req_json")
	assert.NotContains(t, string(raw), "resp_json")
}

func TestActiveAPIEngineAdapterRejectsMismatchedResultMetadata(t *testing.T) {
	adapter := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":200,"msg":"ok","data":{"taskid":"other-task","total_targets":1,` +
					`"finished_targets":1,"page":1,"page_size":50,"results":[]}}`,
			)),
		}, nil
	}})

	_, err := adapter.FetchResultPage(
		context.Background(),
		"active-port-1",
		TaskTypePortProbe,
		1,
		activeAPIResultPageSize,
	)
	assert.ErrorIs(t, err, ErrEngineResult)
}

func TestActiveAPIEngineAdapterRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "task id mismatch",
			body: `{"code":200,"msg":"ok","data":{"taskid":"other","scan_type":"webscan","status":"running","progress":"1%","total_pages":"1","total_targets":"1","finished_targets":0,"create_time":"1"}}`,
		},
		{
			name: "invalid task id",
			body: `{"code":200,"msg":"ok","data":{"taskid":"job\n1","scan_type":"webscan","status":"running","progress":"1%","total_pages":"1","total_targets":"1","finished_targets":0,"create_time":"1"}}`,
		},
		{
			name: "unknown status",
			body: `{"code":200,"msg":"ok","data":{"taskid":"job-1","scan_type":"webscan","status":"mystery","progress":"1%","total_pages":"1","total_targets":"1","finished_targets":0,"create_time":"1"}}`,
		},
		{
			name: "invalid progress",
			body: `{"code":200,"msg":"ok","data":{"taskid":"job-1","scan_type":"webscan","status":"running","progress":"101%","total_pages":"1","total_targets":"1","finished_targets":0,"create_time":"1"}}`,
		},
		{
			name: "unexpected field",
			body: `{"code":200,"msg":"ok","data":{"taskid":"job-1","scan_type":"webscan","status":"running","progress":"1%","total_pages":"1","total_targets":"1","finished_targets":0,"create_time":"1","secret":"unexpected"}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adapter := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(tc.body)),
				}, nil
			}})
			_, err := adapter.Status(context.Background(), "job-1")
			assert.ErrorIs(t, err, ErrEngineStatus)
		})
	}
}

func TestActiveAPIEngineAdapterRejectsOversizedResponseAndUnsupportedCancel(t *testing.T) {
	calls := 0
	adapter := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", engineMaxResponseBody+1))),
		}, nil
	}})

	_, err := adapter.Status(context.Background(), "job-1")
	assert.ErrorIs(t, err, ErrEngineStatus)
	assert.Equal(t, 1, calls)

	err = adapter.Cancel(context.Background(), "job-1")
	assert.ErrorIs(t, err, ErrEngineCancel)
	assert.ErrorIs(t, err, ErrActiveEngineCancelUnsupported)
	assert.Equal(t, 1, calls)
}

func TestActiveAPIEngineAdapterClassifiesHTTPFailures(t *testing.T) {
	tests := []struct {
		status    int
		permanent bool
	}{
		{status: http.StatusUnauthorized, permanent: true},
		{status: http.StatusForbidden, permanent: true},
		{status: http.StatusTooManyRequests, permanent: false},
		{status: http.StatusInternalServerError, permanent: false},
	}
	for _, test := range tests {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			adapter := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: test.status,
					Body:       io.NopCloser(strings.NewReader(`{"code":500,"msg":"not exposed","data":null}`)),
				}, nil
			}})

			_, err := adapter.Dispatch(context.Background(), ScanJob{
				RunID:     42,
				ProjectID: 7,
				ScopeID:   11,
				JobType:   TaskTypePortProbe,
				Targets:   []Target{{Type: TargetTypeIP, Value: "203.0.113.10"}},
				Options:   map[string]any{"ports": "80,443"},
			})
			assert.ErrorIs(t, err, ErrEngineDispatch)
			assert.Equal(t, test.permanent, dispatchErrorIsPermanent(err))
			// Upstream bodies and messages are deliberately absent from errors.
			assert.NotContains(t, err.Error(), "not exposed")
		})
	}
}

func TestActiveAPIEngineAdapterClassifiesEnvelopeRateLimitAsRetryable(t *testing.T) {
	adapter := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":429,"msg":"rate limited","data":{"taskid":"","total_targets":0,"total_pages":0,"page_size":0}}`,
			)),
		}, nil
	}})

	_, err := adapter.Dispatch(context.Background(), ScanJob{
		RunID:     42,
		ProjectID: 7,
		ScopeID:   11,
		JobType:   TaskTypePortProbe,
		Targets:   []Target{{Type: TargetTypeIP, Value: "203.0.113.10"}},
		Options:   map[string]any{"ports": "80"},
	})
	assert.ErrorIs(t, err, ErrEngineDispatch)
	assert.False(t, dispatchErrorIsPermanent(err))
	assert.NotContains(t, err.Error(), "rate limited")
}

func TestActiveAPIEngineAdapterPreservesTransportTimeout(t *testing.T) {
	adapter := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	}})

	_, err := adapter.Dispatch(context.Background(), ScanJob{
		RunID:     42,
		ProjectID: 7,
		ScopeID:   11,
		JobType:   TaskTypePortProbe,
		Targets:   []Target{{Type: TargetTypeIP, Value: "203.0.113.10"}},
		Options:   map[string]any{"ports": "80"},
	})
	assert.ErrorIs(t, err, ErrEngineDispatch)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, dispatchErrorIsPermanent(err))
}

func TestActiveAPIEngineAdapterChecksReadinessWithoutCreatingTask(t *testing.T) {
	calls := 0
	client := fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, activeAPIHealthPath, req.URL.Path)
			assert.Empty(t, req.Header.Get("X-Access-Key"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
			}, nil
		case 2:
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, activeAPINodesPath, req.URL.Path)
			assert.Equal(t, activeAPITestAccessKey, req.Header.Get("X-Access-Key"))
			assert.Equal(t, activeAPISignature(
				activeAPITestSecret,
				http.MethodGet,
				activeAPINodesPath,
				"1785153600",
				activeAPITestNonce,
				nil,
			), req.Header.Get("X-Signature"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(
					`{"code":200,"msg":"ok","data":{"nodes":[` +
						`{"node_id":"node-active-1","status":"online","capabilities":["portscan","webscan"],"ip":"198.51.100.5"}` +
						`]}}`,
				)),
			}, nil
		default:
			t.Fatal("readiness must call only healthz and scan/nodes")
			return nil, nil
		}
	}}

	adapter := newTestActiveAPIAdapter(t, client)
	readiness, err := adapter.CheckReadiness(context.Background())
	require.NoError(t, err)
	assert.True(t, readiness.Ready())
	require.Len(t, readiness.OnlineNodes, 1)
	assert.Equal(t, "node-active-1", readiness.OnlineNodes[0].NodeID)
	assert.Equal(t, []string{"portscan", "webscan"}, readiness.OnlineNodes[0].Capabilities)
	assert.Equal(t, 2, calls)
}

func TestActiveAPIEngineAdapterReportsHealthyWithoutOnlineNodes(t *testing.T) {
	calls := 0
	adapter := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"code":200,"msg":"ok","data":{"nodes":[]}}`)),
		}, nil
	}})

	readiness, err := adapter.CheckReadiness(context.Background())
	require.NoError(t, err)
	assert.False(t, readiness.Ready())
	assert.Empty(t, readiness.OnlineNodes)
	assert.Equal(t, 2, calls)
}

func TestNewActiveAPIEngineAdapterValidatesConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		baseURL    string
		accessKey  string
		secretKey  string
		projectIDs map[uint64]int
	}{
		{name: "invalid scheme", baseURL: "file:///tmp/engine", accessKey: "ak", secretKey: activeAPITestSecret, projectIDs: map[uint64]int{1: 1}},
		{name: "ambiguous base path", baseURL: "https://engine.example.com/custom", accessKey: "ak", secretKey: activeAPITestSecret, projectIDs: map[uint64]int{1: 1}},
		{name: "invalid access key", baseURL: "https://engine.example.com", accessKey: "key with spaces", secretKey: activeAPITestSecret, projectIDs: map[uint64]int{1: 1}},
		{name: "short secret", baseURL: "https://engine.example.com", accessKey: "ak", secretKey: "short", projectIDs: map[uint64]int{1: 1}},
		{name: "invalid mapping", baseURL: "https://engine.example.com", accessKey: "ak", secretKey: activeAPITestSecret, projectIDs: map[uint64]int{1: 0}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewActiveAPIEngineAdapter(tc.baseURL, tc.accessKey, tc.secretKey, tc.projectIDs, nil)
			assert.ErrorIs(t, err, ErrEngineNotConfigured)
		})
	}

	adapter, err := NewActiveAPIEngineAdapter(
		"https://engine.example.com/api/v1/",
		"ak",
		activeAPITestSecret,
		map[uint64]int{7: 101},
		nil,
	)
	require.NoError(t, err)
	client, ok := adapter.client.(*http.Client)
	require.True(t, ok)
	assert.Equal(t, engineHTTPTimeout, client.Timeout)
	require.NotNil(t, client.CheckRedirect)
	assert.ErrorIs(t, client.CheckRedirect(nil, nil), http.ErrUseLastResponse)
}

func TestParseActiveAPIProgressAcceptsDocumentedAndNumericForms(t *testing.T) {
	progress, err := parseActiveAPIProgress(json.RawMessage(`"75%"`))
	require.NoError(t, err)
	assert.Equal(t, 75, progress)

	progress, err = parseActiveAPIProgress(json.RawMessage(`75`))
	require.NoError(t, err)
	assert.Equal(t, 75, progress)
}
