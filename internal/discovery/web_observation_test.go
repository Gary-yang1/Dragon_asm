package discovery

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestExtendedWebResultPreservesObservation(t *testing.T) {
	a := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		var in map[string]json.RawMessage
		require.NoError(t, json.NewDecoder(req.Body).Decode(&in))
		require.NotContains(t, in, "result_version")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":200,"msg":"ok","data":{"taskid":"task-v2","page":1,"page_size":50,"total_targets":1,"finished_targets":1,"results":[{"target":"https://example.test","port":443,"finger_results":[{"name":"nginx","title":"Example","status_code":"200"}],"poc_results":[],"is_vul":false,"web_observation":{"outcome":"responded","final_url":"https://example.test/home","redirect_chain":["https://example.test","https://example.test/home"],"resolved_ips":["192.0.2.1","2001:db8::1"],"connected_ip":"192.0.2.1","cname_chain":["test.cloudfront.net"],"cdn":{"status":"identified","provider":"Amazon CloudFront","evidence":["CNAME: test.cloudfront.net"]},"cloud":{"status":"identified","provider":"AWS"},"observed_at":"2026-09-16T01:00:00Z","rule_version":"dns-http-v1"}}]}}`))}, nil
	}})
	page, err := a.FetchResultPage(context.Background(), "task-v2", TaskTypeWebProbe, 1, 50)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1", page.WebResults[0].Web.ConnectedIP)
	payload, _, err := buildActiveResultPayload(&TaskRun{ID: 11, ProjectID: 5, TaskType: TaskTypeWebProbe, EngineJobID: "task-v2"}, page, time.Now(), hostClassifier{})
	require.NoError(t, err)
	found := false
	for _, f := range payload.Exposures {
		if f.ExposureType == "web" {
			require.NotNil(t, f.Web)
			require.Equal(t, "AWS", f.Web.Cloud.Provider)
			found = true
		}
	}
	require.True(t, found)
}
