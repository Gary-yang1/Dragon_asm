//revive:disable:exported

package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	engineSchemaVersion   = "1.0"
	engineHTTPTimeout     = 30 * time.Second
	engineMaxResponseBody = 1 << 20
)

// HTTPClient is the subset of http.Client used by HTTPEngineAdapter.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPEngineAdapter dispatches jobs to the external owned engine.
type HTTPEngineAdapter struct {
	baseURL string
	token   string
	client  HTTPClient
}

// NewHTTPEngineAdapter builds an HTTP adapter. baseURL must come from trusted config.
func NewHTTPEngineAdapter(baseURL string, token string, client HTTPClient) (*HTTPEngineAdapter, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	token = strings.TrimSpace(token)
	if baseURL == "" || token == "" {
		return nil, ErrEngineNotConfigured
	}
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrEngineNotConfigured
	}
	if client == nil {
		client = &http.Client{Timeout: engineHTTPTimeout}
	}
	return &HTTPEngineAdapter{baseURL: baseURL, token: token, client: client}, nil
}

type dispatchRequest struct {
	SchemaVersion  string         `json:"schema_version"`
	RunID          uint64         `json:"run_id"`
	ProjectID      uint64         `json:"project_id"`
	ScopeID        uint64         `json:"scope_id"`
	JobType        string         `json:"job_type"`
	Targets        []Target       `json:"targets"`
	RateLimit      int            `json:"rate_limit"`
	Concurrency    int            `json:"concurrency"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	CallbackURL    string         `json:"callback_url,omitempty"`
	Options        map[string]any `json:"options,omitempty"`
}

type dispatchResponse struct {
	EngineJobID string `json:"engine_job_id"`
}

type statusResponse struct {
	Status       string `json:"status"`
	Progress     int    `json:"progress"`
	ResultCount  uint64 `json:"result_count"`
	ErrorSummary string `json:"error_summary"`
}

func (a *HTTPEngineAdapter) Dispatch(ctx context.Context, job ScanJob) (string, error) {
	if job.RunID == 0 || job.ProjectID == 0 || job.ScopeID == 0 || !validEngineV1JobType(job.JobType) ||
		len(job.Targets) == 0 || strings.TrimSpace(job.CallbackURL) == "" {
		return "", ErrEngineDispatch
	}
	body, err := json.Marshal(dispatchRequest{
		SchemaVersion:  engineSchemaVersion,
		RunID:          job.RunID,
		ProjectID:      job.ProjectID,
		ScopeID:        job.ScopeID,
		JobType:        job.JobType,
		Targets:        job.Targets,
		RateLimit:      job.RateLimit,
		Concurrency:    job.Concurrency,
		TimeoutSeconds: int(job.Timeout / time.Second),
		CallbackURL:    job.CallbackURL,
		Options:        job.Options,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/scan", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", strconv.FormatUint(job.RunID, 10))
	req.Header.Set("Authorization", "Bearer "+a.token)

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("%w: status=%d", ErrEngineDispatch, resp.StatusCode)
	}
	var out dispatchResponse
	if err := decodeEngineJSON(resp.Body, &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.EngineJobID) == "" {
		return "", ErrEngineDispatch
	}
	return out.EngineJobID, nil
}

func (a *HTTPEngineAdapter) Cancel(ctx context.Context, engineJobID string) error {
	engineJobID = strings.TrimSpace(engineJobID)
	if engineJobID == "" {
		return ErrEngineCancel
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/scan/"+url.PathEscape(engineJobID)+"/cancel", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return errors.Join(ErrEngineCancel, errors.New("status="+strconv.Itoa(resp.StatusCode)))
	}
	return nil
}

func (a *HTTPEngineAdapter) Status(ctx context.Context, engineJobID string) (EngineJobStatus, error) {
	engineJobID = strings.TrimSpace(engineJobID)
	if engineJobID == "" {
		return EngineJobStatus{}, ErrEngineStatus
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/scan/"+url.PathEscape(engineJobID), nil)
	if err != nil {
		return EngineJobStatus{}, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.client.Do(req)
	if err != nil {
		return EngineJobStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return EngineJobStatus{}, fmt.Errorf("%w: status=%d", ErrEngineStatus, resp.StatusCode)
	}
	var out statusResponse
	if err := decodeEngineJSON(resp.Body, &out); err != nil {
		return EngineJobStatus{}, err
	}
	out.Status = strings.TrimSpace(out.Status)
	if !validEngineJobStatus(out.Status) || out.Progress < 0 || out.Progress > 100 {
		return EngineJobStatus{}, ErrEngineStatus
	}
	return EngineJobStatus(out), nil
}

func decodeEngineJSON(body io.Reader, out any) error {
	raw, err := io.ReadAll(io.LimitReader(body, engineMaxResponseBody+1))
	if err != nil {
		return err
	}
	if len(raw) > engineMaxResponseBody {
		return ErrEngineStatus
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrEngineStatus
	}
	return nil
}

func validEngineV1JobType(jobType string) bool {
	return jobType == TaskTypePassiveIntel || jobType == TaskTypeDNS
}

func validEngineJobStatus(status string) bool {
	switch status {
	case EngineJobStatusRunning, EngineJobStatusSuccess, EngineJobStatusPartialSuccess, EngineJobStatusFailed, EngineJobStatusCancelled:
		return true
	default:
		return false
	}
}
