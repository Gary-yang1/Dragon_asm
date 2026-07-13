package engine

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"baiyan/internal/contract"
	"baiyan/internal/job"
)

const maxScanRequestBody = 2 << 20

type JobService interface {
	Submit(request contract.ScanRequest, idempotencyKey string) (job.Record, bool, error)
	Get(jobID string) (job.Record, error)
	Cancel(jobID string) (job.Record, error)
}

type Handler struct {
	jobs                  JobService
	token                 string
	allowedCallbackOrigin string
}

func NewHandler(jobs JobService, token, allowedCallbackOrigin string) (*Handler, error) {
	token = strings.TrimSpace(token)
	if jobs == nil || token == "" {
		return nil, errors.New("baiyan engine: jobs and token are required")
	}
	origin, err := normalizedOrigin(allowedCallbackOrigin)
	if err != nil {
		return nil, err
	}
	return &Handler{jobs: jobs, token: token, allowedCallbackOrigin: origin}, nil
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/scan", h.scan)
	mux.HandleFunc("/scan/", h.job)
	return mux
}

func (h *Handler) scan(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		writeError(w, http.StatusUnauthorized, "INVALID_AUTH", "invalid engine authentication")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxScanRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request contract.ScanRequest
	if err := decoder.Decode(&request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "scan request exceeds 2 MiB")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid scan request")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request must contain one JSON object")
		return
	}
	if err := validateScanRequest(request, h.allowedCallbackOrigin); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "INVALID_PROFILE", "scan request violates passive profile policy")
		return
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if err := job.ValidateIdempotencyKey(request.RunID, idempotencyKey); err != nil {
		writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "idempotency key must equal run_id")
		return
	}
	record, _, err := h.jobs.Submit(request, idempotencyKey)
	if errors.Is(err, job.ErrIdempotencyConflict) {
		writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "run_id was submitted with a different request")
		return
	}
	if errors.Is(err, job.ErrQueueUnavailable) {
		writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", "engine queue is temporarily unavailable")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "engine could not persist the job")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"engine_job_id": record.JobID})
}

func (h *Handler) job(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		writeError(w, http.StatusUnauthorized, "INVALID_AUTH", "invalid engine authentication")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/scan/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "JOB_NOT_FOUND", "job not found")
		return
	}
	jobID := parts[0]
	var (
		record job.Record
		err    error
		status int
	)
	switch {
	case r.Method == http.MethodGet && len(parts) == 1:
		record, err = h.jobs.Get(jobID)
		status = http.StatusOK
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "cancel":
		record, err = h.jobs.Cancel(jobID)
		status = http.StatusAccepted
	default:
		writeError(w, http.StatusNotFound, "JOB_NOT_FOUND", "job not found")
		return
	}
	if errors.Is(err, job.ErrNotFound) {
		writeError(w, http.StatusNotFound, "JOB_NOT_FOUND", "job not found")
		return
	}
	if errors.Is(err, job.ErrNotCancellable) {
		writeError(w, http.StatusConflict, "JOB_NOT_CANCELLABLE", "job is not cancellable")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "engine job operation failed")
		return
	}
	publicStatus := record.Status
	if publicStatus == job.StatusQueued {
		publicStatus = job.StatusRunning
	}
	writeJSON(w, status, map[string]any{
		"status": publicStatus, "progress": record.Progress,
		"result_count": record.ResultCount, "error_summary": record.ErrorSummary,
	})
}

func (h *Handler) authorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	return provided != "" && hmac.Equal([]byte(provided), []byte(h.token))
}

func validateScanRequest(request contract.ScanRequest, allowedOrigin string) error {
	if request.SchemaVersion != contract.SchemaVersion || request.RunID == 0 || request.ProjectID == 0 || request.ScopeID == 0 ||
		len(request.Targets) == 0 || len(request.Targets) > 1000 || request.RateLimit < 1 || request.RateLimit > 10000 ||
		request.Concurrency < 1 || request.Concurrency > 500 || request.TimeoutSeconds < 1 || request.TimeoutSeconds > 86400 {
		return errors.New("invalid request")
	}
	callbackURL, err := url.Parse(strings.TrimSpace(request.CallbackURL))
	if err != nil || callbackURL.User != nil || originFromURL(callbackURL) != allowedOrigin ||
		callbackURL.Path != "/api/v1/discovery/callback" || callbackURL.Query().Get("project_id") != strconv.FormatUint(request.ProjectID, 10) ||
		callbackURL.Query().Get("run_id") != strconv.FormatUint(request.RunID, 10) {
		return errors.New("invalid callback URL")
	}
	profile, _ := request.Options["profile"].(string)
	maxResults, ok := numberOption(request.Options["max_results"])
	if !ok || maxResults < 1 || maxResults > 10000 {
		return errors.New("invalid result limit")
	}
	allowedOptionKeys := map[string]bool{"profile": true, "max_results": true}
	switch request.JobType {
	case "passive_intel":
		if profile != contract.ProfileSubdomainPassive || !validStringListOption(request.Options["sources"], 1, 16, map[string]bool{
			"subfinder": true, "fofa": true, "quake": true, "hunter": true, "certificate_transparency": true,
		}) {
			return errors.New("invalid passive options")
		}
		allowedOptionKeys["sources"] = true
		for _, target := range request.Targets {
			if target.Type != "domain" || normalizeHost(target.Value) == "" {
				return errors.New("passive profile accepts domain only")
			}
		}
	case "dns":
		if profile != contract.ProfileResolve || !validStringListOption(request.Options["record_types"], 1, 3, map[string]bool{"A": true, "AAAA": true, "CNAME": true}) {
			return errors.New("invalid DNS options")
		}
		allowedOptionKeys["record_types"] = true
		for _, target := range request.Targets {
			if (target.Type != "domain" && target.Type != "subdomain") || normalizeHost(target.Value) == "" {
				return errors.New("DNS profile accepts domain/subdomain only")
			}
		}
	default:
		return errors.New("active profile is disabled")
	}
	for key := range request.Options {
		if !allowedOptionKeys[key] {
			return errors.New("unknown or unsafe option")
		}
	}
	return nil
}

func numberOption(value any) (int, bool) {
	number, ok := value.(float64)
	if !ok || number < 1 || number > 10000 || number != float64(int(number)) {
		return 0, false
	}
	return int(number), true
}

func validStringListOption(value any, minItems, maxItems int, allowed map[string]bool) bool {
	items, ok := value.([]any)
	if !ok || len(items) < minItems || len(items) > maxItems {
		return false
	}
	seen := make(map[string]bool)
	for _, item := range items {
		text, ok := item.(string)
		if !ok || !allowed[text] || seen[text] {
			return false
		}
		seen[text] = true
	}
	return true
}

func normalizeHost(value string) string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return ""
			}
		}
	}
	return value
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}
