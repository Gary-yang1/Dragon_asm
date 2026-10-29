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
	engineManagementPath  = "/management/status"
)

// HTTPClient is the subset of http.Client used by HTTPEngineAdapter.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPEngineAdapter dispatches jobs to the external owned engine.
type HTTPEngineAdapter struct {
	configurationVersion uint64
	providerSettings     *ProviderSettings
	baseURL              string
	token                string
	client               HTTPClient
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
		client = &http.Client{
			Timeout: engineHTTPTimeout,
			// The engine protocol never redirects. Following one would let a
			// compromised or misconfigured engine bounce the worker at an arbitrary
			// host — including cloud metadata — and Go replays the request body
			// (project/run/scope IDs and the callback URL) even though it strips the
			// Authorization header cross-host. The engine side already disables
			// redirects in both of its own clients; this makes the two consistent.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &HTTPEngineAdapter{baseURL: baseURL, token: token, client: client}, nil
}

type dispatchRequest struct {
	ConfigurationVersion uint64         `json:"configuration_version,omitempty"`
	SchemaVersion        string         `json:"schema_version"`
	RunID                uint64         `json:"run_id"`
	ProjectID            uint64         `json:"project_id"`
	ScopeID              uint64         `json:"scope_id"`
	JobType              string         `json:"job_type"`
	Targets              []Target       `json:"targets"`
	RateLimit            int            `json:"rate_limit"`
	Concurrency          int            `json:"concurrency"`
	TimeoutSeconds       int            `json:"timeout_seconds"`
	CallbackURL          string         `json:"callback_url,omitempty"`
	Options              map[string]any `json:"options,omitempty"`
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

// PassiveEngineCredentialStatus is already masked by the Baiyan process. ASM
// validates it again before returning it to a platform administrator.
type PassiveEngineCredentialStatus struct {
	Key         string `json:"key"`
	Configured  bool   `json:"configured"`
	MaskedValue string `json:"masked_value"`
}

type PassiveEngineProviderStatus struct {
	Key         string                          `json:"key"`
	Name        string                          `json:"name"`
	Configured  bool                            `json:"configured"`
	Credentials []PassiveEngineCredentialStatus `json:"credentials"`
}

type PassiveEngineManagementStatus struct {
	Status       string                        `json:"status"`
	EngineID     string                        `json:"engine_id"`
	Capabilities []string                      `json:"capabilities"`
	Providers    []PassiveEngineProviderStatus `json:"providers"`
}

// CheckManagementStatus calls Baiyan's authenticated, read-only status route.
// It does not create a scan or call any passive-intelligence provider.
func (a *HTTPEngineAdapter) CheckManagementStatus(ctx context.Context) (PassiveEngineManagementStatus, error) {
	if a == nil {
		return PassiveEngineManagementStatus{}, ErrEngineNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+engineManagementPath, nil)
	if err != nil {
		return PassiveEngineManagementStatus{}, ErrEngineStatus
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.client.Do(req)
	if err != nil {
		return PassiveEngineManagementStatus{}, fmt.Errorf("%w: management request failed", ErrEngineStatus)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return PassiveEngineManagementStatus{}, &engineStatusError{sentinel: ErrEngineStatus, status: resp.StatusCode}
	}
	var out PassiveEngineManagementStatus
	if err := decodeEngineJSON(resp.Body, &out); err != nil {
		return PassiveEngineManagementStatus{}, errors.Join(ErrEngineStatus, err)
	}
	if !strings.EqualFold(strings.TrimSpace(out.Status), "ready") ||
		strings.TrimSpace(out.EngineID) == "" || len(out.Capabilities) > 64 || len(out.Providers) > 32 {
		return PassiveEngineManagementStatus{}, ErrEngineStatus
	}
	for _, provider := range out.Providers {
		if strings.TrimSpace(provider.Key) == "" || strings.TrimSpace(provider.Name) == "" || len(provider.Credentials) > 16 {
			return PassiveEngineManagementStatus{}, ErrEngineStatus
		}
	}
	return out, nil
}

func (a *HTTPEngineAdapter) Dispatch(ctx context.Context, job ScanJob) (string, error) {
	if job.RunID == 0 || job.ProjectID == 0 || job.ScopeID == 0 || !validEngineV1JobType(job.JobType) ||
		len(job.Targets) == 0 || strings.TrimSpace(job.CallbackURL) == "" {
		// Nothing about this payload will change between attempts.
		return "", ErrEngineJobRejected
	}
	if err := a.ensureProviderConfiguration(ctx); err != nil {
		return "", err
	}
	body, err := json.Marshal(dispatchRequest{
		ConfigurationVersion: a.configurationVersion,
		SchemaVersion:        engineSchemaVersion,
		RunID:                job.RunID,
		ProjectID:            job.ProjectID,
		ScopeID:              job.ScopeID,
		JobType:              job.JobType,
		Targets:              job.Targets,
		RateLimit:            job.RateLimit,
		Concurrency:          job.Concurrency,
		TimeoutSeconds:       int(job.Timeout / time.Second),
		CallbackURL:          job.CallbackURL,
		Options:              engineExecutionOptions(job.Options),
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
		failure := &engineStatusError{sentinel: ErrEngineDispatch, status: resp.StatusCode}
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&envelope) == nil {
			switch envelope.Error.Code {
			case "INVALID_PROFILE", "CONFIGURATION_UNAVAILABLE", "INVALID_REQUEST", "INVALID_AUTH":
				failure.code = envelope.Error.Code
			}
		}
		return "", failure
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
		return EngineJobStatus{}, &engineStatusError{sentinel: ErrEngineStatus, status: resp.StatusCode}
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
	route, err := EngineRouteForTaskType(jobType)
	return err == nil && route == EngineRoutePassive
}

func validEngineJobStatus(status string) bool {
	switch status {
	case EngineJobStatusRunning, EngineJobStatusSuccess, EngineJobStatusPartialSuccess, EngineJobStatusFailed, EngineJobStatusCancelled:
		return true
	default:
		return false
	}
}

// engineStatusError records the HTTP status the engine answered with. It unwraps to
// the matching sentinel so existing errors.Is checks keep working, while letting
// the dispatcher classify 4xx (permanent: the engine refused this request) apart
// from 5xx and transport faults (worth retrying).
type engineStatusError struct {
	sentinel error
	status   int
	code     string
}

func (e *engineStatusError) Error() string {
	if e.code != "" {
		return fmt.Sprintf("%v: status=%d code=%s", e.sentinel, e.status, e.code)
	}
	return fmt.Sprintf("%v: status=%d", e.sentinel, e.status)
}

func (e *engineStatusError) Unwrap() error { return e.sentinel }

// permanent reports whether the engine rejected the request itself. Request
// timeout, Too Early and rate-limit responses are transient even though they are
// 4xx; retrying those after backoff is expected.
func (e *engineStatusError) permanent() bool {
	if e.status == http.StatusRequestTimeout ||
		e.status == http.StatusTooEarly ||
		e.status == http.StatusTooManyRequests {
		return false
	}
	return e.status >= 400 && e.status < 500
}

// Blueprint scheduling metadata belongs to ASM, not to the engine execution
// contract. Copy the map so the stored template and audit snapshot stay intact.
// Unknown keys are intentionally retained for the engine to reject strictly.
func engineExecutionOptions(options map[string]any) map[string]any {
	if options == nil {
		return nil
	}
	out := make(map[string]any, len(options))
	for key, value := range options {
		switch key {
		case "blueprint_key", "blueprint_version", "blueprint_scope_id", "blueprint_step_key", "depends_on", "target_selection":
			continue
		}
		out[key] = value
	}
	return out
}
