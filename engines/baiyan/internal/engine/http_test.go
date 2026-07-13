package engine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"baiyan/internal/contract"
	"baiyan/internal/job"
)

type fakeJobs struct {
	request contract.ScanRequest
	key     string
	record  job.Record
	err     error
}

func (f *fakeJobs) Submit(request contract.ScanRequest, key string) (job.Record, bool, error) {
	f.request, f.key = request, key
	return f.record, false, f.err
}
func (f *fakeJobs) Get(_ string) (job.Record, error)    { return f.record, f.err }
func (f *fakeJobs) Cancel(_ string) (job.Record, error) { return f.record, f.err }

func validHTTPScanRequest() map[string]any {
	return map[string]any{
		"schema_version": "1.0", "run_id": 7, "project_id": 3, "scope_id": 2, "job_type": "passive_intel",
		"targets":    []any{map[string]any{"type": "domain", "value": "example.com"}},
		"rate_limit": 10, "concurrency": 2, "timeout_seconds": 30,
		"callback_url": "https://asm.example.com/api/v1/discovery/callback?project_id=3&run_id=7",
		"options":      map[string]any{"profile": "subdomain_passive", "sources": []any{"certificate_transparency"}, "max_results": 100},
	}
}

func TestHTTPFacadeStrictAuthContractAndCancel(t *testing.T) {
	jobs := &fakeJobs{record: job.Record{JobID: "job-7", Status: job.StatusQueued, Progress: 0, CreatedAt: time.Now()}}
	handler, err := NewHandler(jobs, "engine-token", "https://asm.example.com")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(validHTTPScanRequest())
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer engine-token")
	req.Header.Set("Idempotency-Key", "7")
	w := httptest.NewRecorder()
	handler.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted || jobs.request.RunID != 7 || jobs.key != "7" {
		t.Fatalf("unexpected submit response: code=%d body=%s request=%+v", w.Code, w.Body.String(), jobs.request)
	}

	jobs.record.Status = job.StatusRunning
	req = httptest.NewRequest(http.MethodPost, "/scan/job-7/cancel", nil)
	req.Header.Set("Authorization", "Bearer engine-token")
	w = httptest.NewRecorder()
	handler.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("unexpected cancel response: %d %s", w.Code, w.Body.String())
	}
}

func TestHTTPFacadeRejectsUnknownUnsafeAndConflictingRequests(t *testing.T) {
	jobs := &fakeJobs{record: job.Record{JobID: "job-7"}}
	handler, _ := NewHandler(jobs, "engine-token", "https://asm.example.com")
	tests := []struct {
		name   string
		mutate func(map[string]any)
		key    string
		status int
	}{
		{name: "unknown top field", mutate: func(v map[string]any) { v["command"] = "masscan" }, key: "7", status: http.StatusBadRequest},
		{name: "unsafe option", mutate: func(v map[string]any) { v["options"].(map[string]any)["credential"] = "secret" }, key: "7", status: http.StatusUnprocessableEntity},
		{name: "active job type", mutate: func(v map[string]any) { v["job_type"] = "port_probe" }, key: "7", status: http.StatusUnprocessableEntity},
		{name: "callback origin", mutate: func(v map[string]any) {
			v["callback_url"] = "https://evil.invalid/api/v1/discovery/callback?project_id=3&run_id=7"
		}, key: "7", status: http.StatusUnprocessableEntity},
		{name: "idempotency", mutate: func(map[string]any) {}, key: "8", status: http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := validHTTPScanRequest()
			tt.mutate(value)
			body, _ := json.Marshal(value)
			req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer engine-token")
			req.Header.Set("Idempotency-Key", tt.key)
			w := httptest.NewRecorder()
			handler.Routes().ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Fatalf("want %d got %d: %s", tt.status, w.Code, w.Body.String())
			}
		})
	}

	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	handler.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer token was not rejected: %d", w.Code)
	}
}

func TestHTTPFacadeRejectsBodyAboveContractLimit(t *testing.T) {
	handler, err := NewHandler(&fakeJobs{}, "engine-token", "https://asm.example.com")
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte{' '}, maxScanRequestBody+1)
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer engine-token")
	w := httptest.NewRecorder()
	handler.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want %d got %d: %s", http.StatusRequestEntityTooLarge, w.Code, w.Body.String())
	}
}
