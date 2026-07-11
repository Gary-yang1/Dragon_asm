//revive:disable:exported

package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	if baseURL == "" {
		return nil, ErrEngineNotConfigured
	}
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, ErrEngineNotConfigured
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPEngineAdapter{baseURL: baseURL, token: token, client: client}, nil
}

type dispatchRequest struct {
	RunID          string         `json:"run_id"`
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
	ResultCount  uint64 `json:"result_count"`
	ErrorSummary string `json:"error_summary"`
}

func (a *HTTPEngineAdapter) Dispatch(ctx context.Context, job ScanJob) (string, error) {
	if strings.TrimSpace(job.RunID) == "" || strings.TrimSpace(job.JobType) == "" || len(job.Targets) == 0 {
		return "", ErrEngineDispatch
	}
	body, err := json.Marshal(dispatchRequest{
		RunID:          job.RunID,
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
	req.Header.Set("Idempotency-Key", job.RunID)
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("%w: status=%d", ErrEngineDispatch, resp.StatusCode)
	}
	var out dispatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
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
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return EngineJobStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return EngineJobStatus{}, fmt.Errorf("%w: status=%d", ErrEngineStatus, resp.StatusCode)
	}
	var out statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return EngineJobStatus{}, err
	}
	out.Status = strings.TrimSpace(out.Status)
	if out.Status == "" {
		return EngineJobStatus{}, ErrEngineStatus
	}
	return EngineJobStatus(out), nil
}
