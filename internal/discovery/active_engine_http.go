//revive:disable:exported

package discovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Gary-yang1/Dragon_asm/internal/webview"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	activeAPIPathPrefix       = "/api/v1"
	activeAPIPortScanPath     = activeAPIPathPrefix + "/portscan"
	activeAPIWebScanPath      = activeAPIPathPrefix + "/webscan"
	activeAPIStatusPath       = activeAPIPathPrefix + "/status"
	activeAPIPortResultPath   = activeAPIPathPrefix + "/result/portscan"
	activeAPIWebResultPath    = activeAPIPathPrefix + "/result/webscan"
	activeAPIHealthPath       = activeAPIPathPrefix + "/healthz"
	activeAPINodesPath        = activeAPIPathPrefix + "/scan/nodes"
	activeAPIMinSecretKeyLen  = 32
	activeAPIMaxTargets       = 1000
	activeAPIMaxExpandedPorts = 1000
	activeAPIMaxOnlineNodes   = 1000
	activeAPIMaxCapabilities  = 32
	activeAPIMaxAccessKeyLen  = 128
	activeAPIMaxNodeIDLen     = 128
	activeAPIMaxTaskIDLen     = 128
	activeAPIResultPageSize   = 50
	activeAPIMaxResultTextLen = 2048
	activeAPIMaxPortsTextLen  = 6000
	activeAPIMaxFingerprints  = 32
)

var (
	ErrActiveEngineProjectMapping    = fmt.Errorf("%w: 当前项目尚未配置主动引擎项目映射，请在系统设置的引擎配置中绑定对应项目", ErrEngineDispatch)
	ErrActiveEngineCancelUnsupported = fmt.Errorf(
		"%w: active engine API does not expose cancellation",
		ErrEngineCancel,
	)
)

// ActiveAPIEngineAdapter implements the node service's AK/SK API contract.
//
// Runtime configuration can select this adapter for active task types. Dispatch
// carries a stable request_id derived from the ASM run so retrying the same run
// does not create another active-engine task. Cancellation and result lifecycle
// integration are handled separately.
type ActiveAPIEngineAdapter struct {
	baseURL         string
	accessKey       string
	secretKey       string
	projectIDs      map[uint64]int
	projectResolver engineProjectResolver
	client          HTTPClient
	now             func() time.Time
	nonce           func() (string, error)
}

// NewActiveAPIEngineAdapter builds an AK/SK client for a trusted active-engine
// endpoint. projectIDs is an explicit ASM-project to engine-project mapping.
func NewActiveAPIEngineAdapter(
	baseURL string,
	accessKey string,
	secretKey string,
	projectIDs map[uint64]int,
	client HTTPClient,
) (*ActiveAPIEngineAdapter, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" ||
		!validActiveAPIIdentifier(accessKey, activeAPIMaxAccessKeyLen) ||
		secretKey == "" || secretKey != strings.TrimSpace(secretKey) ||
		len(secretKey) < activeAPIMinSecretKeyLen {
		return nil, ErrEngineNotConfigured
	}

	u, err := url.Parse(baseURL)
	if err != nil ||
		(u.Scheme != httpScheme && u.Scheme != httpsScheme) ||
		u.Host == "" ||
		u.User != nil ||
		u.RawQuery != "" ||
		u.Fragment != "" ||
		u.RawPath != "" {
		return nil, ErrEngineNotConfigured
	}

	switch strings.TrimRight(u.Path, "/") {
	case "":
		u.Path = activeAPIPathPrefix
	case activeAPIPathPrefix:
		u.Path = activeAPIPathPrefix
	default:
		return nil, ErrEngineNotConfigured
	}

	projectMap := make(map[uint64]int, len(projectIDs))
	for asmProjectID, engineProjectID := range projectIDs {
		if asmProjectID == 0 || engineProjectID <= 0 {
			return nil, ErrEngineNotConfigured
		}
		projectMap[asmProjectID] = engineProjectID
	}

	if client == nil {
		client = &http.Client{
			Timeout: engineHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &ActiveAPIEngineAdapter{
		baseURL:    strings.TrimRight(u.String(), "/"),
		accessKey:  accessKey,
		secretKey:  secretKey,
		projectIDs: projectMap,
		client:     client,
		now:        time.Now,
		nonce:      newActiveAPINonce,
	}, nil
}

type activeAPIPortScanRequest struct {
	ProjectID int      `json:"project_id"`
	RequestID string   `json:"request_id"`
	TaskName  string   `json:"task_name"`
	NodeID    string   `json:"node_id,omitempty"`
	Targets   []string `json:"targets"`
	Ports     string   `json:"ports"`
}

type activeAPIWebScanRequest struct {
	ProjectID int      `json:"project_id"`
	RequestID string   `json:"request_id"`
	TaskName  string   `json:"task_name"`
	NodeID    string   `json:"node_id,omitempty"`
	NoPOC     bool     `json:"nopoc"`
	URLs      []string `json:"urls"`
}

type activeAPITaskIDRequest struct {
	TaskID string `json:"taskid"`
}

type activeAPIResultRequest struct {
	TaskID   string `json:"taskid"`
	Page     int    `json:"page"`
	PageSize int    `json:"pagesize"`
}

type activeAPIDispatchData struct {
	TaskID           string `json:"taskid"`
	TotalTargets     int    `json:"total_targets"`
	TotalPages       int    `json:"total_pages"`
	PageSize         int    `json:"page_size"`
	IdempotentReplay bool   `json:"idempotent_replay"`
}

type activeAPIStatusData struct {
	TaskID          string          `json:"taskid"`
	ScanType        string          `json:"scan_type"`
	Status          string          `json:"status"`
	Progress        json.RawMessage `json:"progress"`
	TotalPages      json.RawMessage `json:"total_pages"`
	TotalTargets    json.RawMessage `json:"total_targets"`
	FinishedTargets int             `json:"finished_targets"`
	CreateTime      json.RawMessage `json:"create_time"`
}

type activeAPIEnvelope[T any] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

type activeAPIHealthResponse struct {
	Status string `json:"status"`
}

type activeAPINodesData struct {
	Nodes []json.RawMessage `json:"nodes"`
}

type activeAPINode struct {
	NodeID       string   `json:"node_id"`
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
}

type activeAPIResultData[T any] struct {
	TaskID          string `json:"taskid"`
	Status          string `json:"status,omitempty"`
	TotalTargets    int    `json:"total_targets"`
	FinishedTargets int    `json:"finished_targets"`
	VisibleResults  *int   `json:"visible_results,omitempty"`
	Page            int    `json:"page"`
	PageSize        int    `json:"page_size"`
	Results         []T    `json:"results"`
}

type activeAPIPortResult struct {
	Target string `json:"target"`
	Ports  string `json:"ports"`
}

type activeAPIWebResult struct {
	Web           *webview.Observation      `json:"web_observation,omitempty"`
	Target        string                    `json:"target"`
	Port          int                       `json:"port"`
	FingerResults []activeAPIWebFingerprint `json:"finger_results"`
	PocResults    []json.RawMessage         `json:"poc_results"`
	IsVul         bool                      `json:"is_vul"`
}

type activeAPIWebFingerprint struct {
	Name       string `json:"name"`
	StatusCode string `json:"status_code"`
	Title      string `json:"title"`
}

// ActiveEngineNode is the non-sensitive subset ASM needs for readiness and
// future task selection.
type ActiveEngineNode struct {
	NodeID       string
	Capabilities []string
}

// ActiveEngineReadiness reports whether the active API has an online executor.
// A successful check with zero nodes is healthy-but-not-ready, not an API error.
type ActiveEngineReadiness struct {
	OnlineNodes []ActiveEngineNode
}

// Ready reports whether at least one online active-engine node can accept work.
func (r ActiveEngineReadiness) Ready() bool {
	return len(r.OnlineNodes) > 0
}

func (a *ActiveAPIEngineAdapter) Dispatch(ctx context.Context, job ScanJob) (string, error) {
	if job.RunID == 0 || job.ProjectID == 0 || job.ScopeID == 0 || len(job.Targets) == 0 {
		return "", ErrEngineJobRejected
	}
	if len(job.Targets) > activeAPIMaxTargets {
		return "", ErrEngineJobRejected
	}

	engineProjectID := a.projectIDs[job.ProjectID]

	nodeID, err := activeAPIStringOption(job.Options, "node_id")
	if err != nil || !validActiveAPINodeID(nodeID) {
		return "", ErrEngineJobRejected
	}

	var path string
	var payload any
	switch job.JobType {
	case TaskTypePortProbe:
		ports, optionErr := activeAPIStringOption(job.Options, "ports")
		if optionErr != nil || !validActiveAPIPorts(ports) {
			return "", ErrEngineJobRejected
		}
		targets, targetErr := activeAPIPortTargets(job.Targets)
		if targetErr != nil {
			return "", ErrEngineJobRejected
		}
		path = activeAPIPortScanPath
		payload = activeAPIPortScanRequest{
			ProjectID: engineProjectID,
			RequestID: activeAPIRequestID(job),
			TaskName:  activeAPITaskName(job),
			NodeID:    nodeID,
			Targets:   targets,
			Ports:     ports,
		}
	case TaskTypeWebProbe, TaskTypeFingerprint:
		targets, targetErr := activeAPIWebTargets(job.Targets)
		if targetErr != nil {
			return "", ErrEngineJobRejected
		}
		path = activeAPIWebScanPath
		payload = activeAPIWebScanRequest{
			ProjectID: engineProjectID,
			RequestID: activeAPIRequestID(job),
			TaskName:  activeAPITaskName(job),
			NodeID:    nodeID,
			// ASM exposure discovery is read-only. Never let template options
			// turn on the node service's PoC execution.
			NoPOC: true,
			URLs:  targets,
		}
	default:
		return "", ErrEngineJobRejected
	}

	if engineProjectID <= 0 {
		if a.projectResolver == nil {
			return "", errors.Join(ErrEngineJobRejected, ErrActiveEngineProjectMapping)
		}
		engineProjectID, err = a.projectResolver.Resolve(ctx, a, job.ProjectID)
		if err != nil {
			return "", err
		}
		if engineProjectID <= 0 {
			return "", ErrEngineProjectSetup
		}
		switch request := payload.(type) {
		case activeAPIPortScanRequest:
			request.ProjectID = engineProjectID
			payload = request
		case activeAPIWebScanRequest:
			request.ProjectID = engineProjectID
			payload = request
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: encode request", ErrEngineDispatch)
	}
	resp, err := a.doSignedJSON(ctx, http.MethodPost, path, body)
	if err != nil {
		return "", fmt.Errorf("%w: request failed: %w", ErrEngineDispatch, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", &engineStatusError{sentinel: ErrEngineDispatch, status: resp.StatusCode}
	}

	var out activeAPIEnvelope[activeAPIDispatchData]
	if err := decodeActiveAPIJSON(resp.Body, &out, ErrEngineDispatch); err != nil {
		return "", err
	}
	if out.Code != http.StatusOK {
		return "", activeAPIResponseError(ErrEngineDispatch, out.Code)
	}
	out.Data.TaskID = strings.TrimSpace(out.Data.TaskID)
	if !validActiveAPIIdentifier(out.Data.TaskID, activeAPIMaxTaskIDLen) ||
		out.Data.TotalTargets != len(job.Targets) ||
		out.Data.TotalPages <= 0 ||
		out.Data.PageSize <= 0 {
		return "", ErrEngineDispatch
	}
	return out.Data.TaskID, nil
}

func activeAPIRequestID(job ScanJob) string {
	return fmt.Sprintf("asm:%d:%d", job.ProjectID, job.RunID)
}

func (a *ActiveAPIEngineAdapter) Cancel(context.Context, string) error {
	return ErrActiveEngineCancelUnsupported
}

func (a *ActiveAPIEngineAdapter) Status(ctx context.Context, engineJobID string) (EngineJobStatus, error) {
	engineJobID = strings.TrimSpace(engineJobID)
	if !validActiveAPIIdentifier(engineJobID, activeAPIMaxTaskIDLen) {
		return EngineJobStatus{}, ErrEngineStatus
	}

	body, err := json.Marshal(activeAPITaskIDRequest{TaskID: engineJobID})
	if err != nil {
		return EngineJobStatus{}, fmt.Errorf("%w: encode request", ErrEngineStatus)
	}
	resp, err := a.doSignedJSON(ctx, http.MethodPost, activeAPIStatusPath, body)
	if err != nil {
		return EngineJobStatus{}, fmt.Errorf("%w: request failed: %w", ErrEngineStatus, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return EngineJobStatus{}, &engineStatusError{sentinel: ErrEngineStatus, status: resp.StatusCode}
	}

	var out activeAPIEnvelope[activeAPIStatusData]
	if err := decodeActiveAPIJSON(resp.Body, &out, ErrEngineStatus); err != nil {
		return EngineJobStatus{}, err
	}
	if out.Code != http.StatusOK {
		return EngineJobStatus{}, activeAPIResponseError(ErrEngineStatus, out.Code)
	}
	out.Data.TaskID = strings.TrimSpace(out.Data.TaskID)
	out.Data.ScanType = strings.TrimSpace(out.Data.ScanType)
	if !validActiveAPIIdentifier(out.Data.TaskID, activeAPIMaxTaskIDLen) ||
		out.Data.TaskID != engineJobID ||
		(out.Data.ScanType != "portscan" && out.Data.ScanType != "webscan") ||
		out.Data.FinishedTargets < 0 {
		return EngineJobStatus{}, ErrEngineStatus
	}

	status, ok := normalizeActiveAPIStatus(out.Data.Status)
	if !ok {
		return EngineJobStatus{}, ErrEngineStatus
	}
	progress, err := parseActiveAPIProgress(out.Data.Progress)
	if err != nil {
		return EngineJobStatus{}, ErrEngineStatus
	}
	return EngineJobStatus{
		Status:   status,
		Progress: progress,
		// The active API reports finished targets, not result rows. Reporting it
		// as ResultCount would corrupt run metrics, so result ingestion owns this.
		ResultCount: 0,
	}, nil
}

// FetchResultPage pulls one bounded result page from the active engine. The
// adapter intentionally discards PoC details at the HTTP boundary; only target,
// port, status/title, and fingerprint names can reach normalization.
func (a *ActiveAPIEngineAdapter) FetchResultPage(
	ctx context.Context,
	engineJobID string,
	taskType string,
	page int,
	pageSize int,
) (EngineResultPage, error) {
	engineJobID = strings.TrimSpace(engineJobID)
	if !validActiveAPIIdentifier(engineJobID, activeAPIMaxTaskIDLen) ||
		page <= 0 ||
		pageSize != activeAPIResultPageSize {
		return EngineResultPage{}, ErrEngineResult
	}

	path := ""
	switch taskType {
	case TaskTypePortProbe:
		path = activeAPIPortResultPath
	case TaskTypeWebProbe, TaskTypeFingerprint:
		path = activeAPIWebResultPath
	default:
		return EngineResultPage{}, ErrEngineResultUnsupported
	}

	request := activeAPIResultRequest{TaskID: engineJobID, Page: page, PageSize: pageSize}
	body, err := json.Marshal(request)
	if err != nil {
		return EngineResultPage{}, fmt.Errorf("%w: encode request", ErrEngineResult)
	}
	resp, err := a.doSignedJSON(ctx, http.MethodPost, path, body)
	if err != nil {
		return EngineResultPage{}, fmt.Errorf("%w: request failed: %w", ErrEngineResult, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return EngineResultPage{}, &engineStatusError{sentinel: ErrEngineResult, status: resp.StatusCode}
	}

	switch taskType {
	case TaskTypePortProbe:
		var out activeAPIEnvelope[activeAPIResultData[activeAPIPortResult]]
		if err := decodeActiveAPIJSON(resp.Body, &out, ErrEngineResult); err != nil {
			return EngineResultPage{}, err
		}
		if out.Code != http.StatusOK {
			return EngineResultPage{}, activeAPIResponseError(ErrEngineResult, out.Code)
		}
		if err := validateActiveAPIResultMetadata(
			out.Data.TaskID,
			engineJobID,
			out.Data.Page,
			page,
			out.Data.PageSize,
			pageSize,
			out.Data.TotalTargets,
			out.Data.FinishedTargets,
			len(out.Data.Results),
			out.Data.VisibleResults,
		); err != nil {
			return EngineResultPage{}, err
		}
		results := make([]EnginePortResult, 0, len(out.Data.Results))
		for _, item := range out.Data.Results {
			item.Target = strings.TrimSpace(item.Target)
			item.Ports = strings.TrimSpace(item.Ports)
			if item.Target == "" || len(item.Target) > activeAPIMaxResultTextLen ||
				len(item.Ports) > activeAPIMaxPortsTextLen {
				return EngineResultPage{}, ErrEngineResult
			}
			results = append(results, EnginePortResult(item))
		}
		return EngineResultPage{
			TaskID: engineJobID, Page: page, PageSize: pageSize,
			TotalTargets: out.Data.TotalTargets, FinishedTargets: out.Data.FinishedTargets,
			PortResults: results,
		}, nil

	case TaskTypeWebProbe, TaskTypeFingerprint:
		var out activeAPIEnvelope[activeAPIResultData[activeAPIWebResult]]
		if err := decodeActiveAPIJSON(resp.Body, &out, ErrEngineResult); err != nil {
			return EngineResultPage{}, err
		}
		if out.Code != http.StatusOK {
			return EngineResultPage{}, activeAPIResponseError(ErrEngineResult, out.Code)
		}
		if err := validateActiveAPIResultMetadata(
			out.Data.TaskID,
			engineJobID,
			out.Data.Page,
			page,
			out.Data.PageSize,
			pageSize,
			out.Data.TotalTargets,
			out.Data.FinishedTargets,
			len(out.Data.Results),
			nil,
		); err != nil {
			return EngineResultPage{}, err
		}
		results := make([]EngineWebResult, 0, len(out.Data.Results))
		for _, item := range out.Data.Results {
			if !item.Web.Valid() {
				return EngineResultPage{}, ErrEngineResult
			}
			item.Target = strings.TrimSpace(item.Target)
			if item.Target == "" || len(item.Target) > activeAPIMaxResultTextLen ||
				item.Port < 0 || item.Port > 65535 ||
				len(item.FingerResults) > activeAPIMaxFingerprints {
				return EngineResultPage{}, ErrEngineResult
			}
			fingerprints := make([]EngineWebFingerprint, 0, len(item.FingerResults))
			for _, finger := range item.FingerResults {
				if len(finger.Name) > activeAPIMaxResultTextLen ||
					len(finger.StatusCode) > activeAPIMaxResultTextLen ||
					len(finger.Title) > activeAPIMaxResultTextLen {
					return EngineResultPage{}, ErrEngineResult
				}
				fingerprints = append(fingerprints, EngineWebFingerprint(finger))
			}
			results = append(results, EngineWebResult{
				Target: item.Target, Port: item.Port, Fingerprints: fingerprints, Web: item.Web,
			})
		}
		return EngineResultPage{
			TaskID: engineJobID, Page: page, PageSize: pageSize,
			TotalTargets: out.Data.TotalTargets, FinishedTargets: out.Data.FinishedTargets,
			WebResults: results,
		}, nil
	default:
		return EngineResultPage{}, ErrEngineResultUnsupported
	}
}

func validateActiveAPIResultMetadata(
	taskID string,
	expectedTaskID string,
	page int,
	expectedPage int,
	pageSize int,
	expectedPageSize int,
	totalTargets int,
	finishedTargets int,
	resultCount int,
	visibleResults *int,
) error {
	taskID = strings.TrimSpace(taskID)
	if !validActiveAPIIdentifier(taskID, activeAPIMaxTaskIDLen) ||
		taskID != expectedTaskID ||
		page != expectedPage ||
		pageSize != expectedPageSize ||
		totalTargets <= 0 ||
		totalTargets > activeAPIMaxTargets ||
		finishedTargets < 0 ||
		finishedTargets > totalTargets ||
		resultCount < 0 ||
		resultCount > pageSize {
		return ErrEngineResult
	}
	if visibleResults != nil && (*visibleResults < 0 || *visibleResults > totalTargets) {
		return ErrEngineResult
	}
	return nil
}

// CheckReadiness verifies both layers documented by the active engine: the
// unauthenticated API liveness endpoint and the signed online-node endpoint. It
// is read-only and never creates a scan.
func (a *ActiveAPIEngineAdapter) CheckReadiness(ctx context.Context) (ActiveEngineReadiness, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		a.baseURL+strings.TrimPrefix(activeAPIHealthPath, activeAPIPathPrefix),
		nil,
	)
	if err != nil {
		return ActiveEngineReadiness{}, fmt.Errorf("%w: build health request", ErrEngineStatus)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return ActiveEngineReadiness{}, fmt.Errorf("%w: health request failed: %w", ErrEngineStatus, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ActiveEngineReadiness{}, &engineStatusError{sentinel: ErrEngineStatus, status: resp.StatusCode}
	}

	var health activeAPIHealthResponse
	if err := decodeActiveAPIJSON(resp.Body, &health, ErrEngineStatus); err != nil {
		return ActiveEngineReadiness{}, err
	}
	if strings.TrimSpace(strings.ToLower(health.Status)) != "ok" {
		return ActiveEngineReadiness{}, ErrEngineStatus
	}

	nodesResp, err := a.doSignedJSON(ctx, http.MethodGet, activeAPINodesPath, nil)
	if err != nil {
		return ActiveEngineReadiness{}, fmt.Errorf("%w: nodes request failed: %w", ErrEngineStatus, err)
	}
	defer func() { _ = nodesResp.Body.Close() }()
	if nodesResp.StatusCode != http.StatusOK {
		return ActiveEngineReadiness{}, &engineStatusError{sentinel: ErrEngineStatus, status: nodesResp.StatusCode}
	}

	var envelope activeAPIEnvelope[activeAPINodesData]
	if err := decodeActiveAPIJSON(nodesResp.Body, &envelope, ErrEngineStatus); err != nil {
		return ActiveEngineReadiness{}, err
	}
	if envelope.Code != http.StatusOK {
		return ActiveEngineReadiness{}, activeAPIResponseError(ErrEngineStatus, envelope.Code)
	}
	nodes, err := normalizeActiveAPINodes(envelope.Data.Nodes)
	if err != nil {
		return ActiveEngineReadiness{}, err
	}
	return ActiveEngineReadiness{OnlineNodes: nodes}, nil
}

func (a *ActiveAPIEngineAdapter) doSignedJSON(
	ctx context.Context,
	method string,
	path string,
	body []byte,
) (*http.Response, error) {
	nonce, err := a.nonce()
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(a.now().Unix(), 10)
	// The engine signs URL.Path; query parameters are not part of its contract.
	signPath := strings.SplitN(path, "?", 2)[0]
	signature := activeAPISignature(a.secretKey, method, signPath, timestamp, nonce, body)

	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+strings.TrimPrefix(path, activeAPIPathPrefix), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Access-Key", a.accessKey)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", signature)
	return a.client.Do(req)
}

func activeAPIResponseError(sentinel error, code int) error {
	if code >= http.StatusBadRequest && code <= 599 {
		return &engineStatusError{sentinel: sentinel, status: code}
	}
	return sentinel
}

func normalizeActiveAPINodes(rawNodes []json.RawMessage) ([]ActiveEngineNode, error) {
	if len(rawNodes) > activeAPIMaxOnlineNodes {
		return nil, ErrEngineStatus
	}
	nodes := make([]ActiveEngineNode, 0, len(rawNodes))
	seen := make(map[string]struct{}, len(rawNodes))
	for _, rawNode := range rawNodes {
		var node activeAPINode
		if err := json.Unmarshal(rawNode, &node); err != nil {
			return nil, ErrEngineStatus
		}
		node.NodeID = strings.TrimSpace(node.NodeID)
		if !validActiveAPIIdentifier(node.NodeID, activeAPIMaxNodeIDLen) ||
			!strings.EqualFold(strings.TrimSpace(node.Status), "online") ||
			len(node.Capabilities) > activeAPIMaxCapabilities {
			return nil, ErrEngineStatus
		}
		if _, exists := seen[node.NodeID]; exists {
			return nil, ErrEngineStatus
		}
		seen[node.NodeID] = struct{}{}

		capabilities := make([]string, 0, len(node.Capabilities))
		for _, capability := range node.Capabilities {
			capability = strings.TrimSpace(capability)
			if !validActiveAPIIdentifier(capability, activeAPIMaxNodeIDLen) {
				return nil, ErrEngineStatus
			}
			capabilities = append(capabilities, capability)
		}
		nodes = append(nodes, ActiveEngineNode{
			NodeID:       node.NodeID,
			Capabilities: capabilities,
		})
	}
	return nodes, nil
}

func activeAPICanonicalString(method, path, timestamp, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.ToUpper(method) + "\n" +
		path + "\n" +
		timestamp + "\n" +
		nonce + "\n" +
		hex.EncodeToString(sum[:])
}

func activeAPISignature(secretKey, method, path, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	_, _ = mac.Write([]byte(activeAPICanonicalString(method, path, timestamp, nonce, body)))
	return hex.EncodeToString(mac.Sum(nil))
}

func newActiveAPINonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func activeAPIStringOption(options map[string]any, key string) (string, error) {
	if options == nil {
		return "", nil
	}
	value, ok := options[key]
	if !ok {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", ErrEngineJobRejected
	}
	return strings.TrimSpace(text), nil
}

func validActiveAPINodeID(nodeID string) bool {
	return nodeID == "" || validActiveAPIIdentifier(nodeID, activeAPIMaxNodeIDLen)
}

func activeAPIPortTargets(targets []Target) ([]string, error) {
	out := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		value := strings.TrimSpace(target.Value)
		if target.Type != TargetTypeIP || net.ParseIP(value) == nil {
			return nil, ErrEngineJobRejected
		}
		if _, exists := seen[value]; exists {
			return nil, ErrEngineJobRejected
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func activeAPIWebTargets(targets []Target) ([]string, error) {
	out := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		value := strings.TrimSpace(target.Value)
		if target.Type != TargetTypeURL || len(value) > maxTargetValue {
			return nil, ErrEngineJobRejected
		}
		u, err := url.ParseRequestURI(value)
		if err != nil ||
			(u.Scheme != httpScheme && u.Scheme != httpsScheme) ||
			u.Host == "" ||
			u.User != nil ||
			u.Fragment != "" {
			return nil, ErrEngineJobRejected
		}
		if _, exists := seen[value]; exists {
			return nil, ErrEngineJobRejected
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func validActiveAPIPorts(raw string) bool {
	if raw == "" || raw == "all" {
		return false
	}

	total := 0
	for _, item := range strings.Split(raw, ",") {
		if item == "" || item != strings.TrimSpace(item) || strings.Count(item, "-") > 1 {
			return false
		}
		bounds := strings.Split(item, "-")
		if !activeAPIASCIIDigits(bounds[0]) {
			return false
		}
		start, err := strconv.Atoi(bounds[0])
		if err != nil || start < 1 || start > 65535 {
			return false
		}
		end := start
		if len(bounds) == 2 {
			if !activeAPIASCIIDigits(bounds[1]) {
				return false
			}
			end, err = strconv.Atoi(bounds[1])
			if err != nil || end < start || end > 65535 {
				return false
			}
		}
		total += end - start + 1
		if total > activeAPIMaxExpandedPorts {
			return false
		}
	}
	return total > 0
}

func activeAPIASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func validActiveAPIIdentifier(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != '-' &&
			char != '_' &&
			char != '.' &&
			char != ':' {
			return false
		}
	}
	return true
}

func activeAPITaskName(job ScanJob) string {
	return fmt.Sprintf("ASM-%s-%d", job.JobType, job.RunID)
}

func normalizeActiveAPIStatus(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "waiting", "pending", "queued", "running", "processing":
		return EngineJobStatusRunning, true
	case "finished", "completed", "success", "succeeded":
		return EngineJobStatusSuccess, true
	case "partial", "partial_success":
		return EngineJobStatusPartialSuccess, true
	case "failed", "error":
		return EngineJobStatusFailed, true
	case "cancelled", "canceled":
		return EngineJobStatusCancelled, true
	default:
		return "", false
	}
}

func parseActiveAPIProgress(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, ErrEngineStatus
	}

	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		var number int
		if numberErr := json.Unmarshal(raw, &number); numberErr != nil {
			return 0, ErrEngineStatus
		}
		if number < 0 || number > 100 {
			return 0, ErrEngineStatus
		}
		return number, nil
	}

	text = strings.TrimSpace(text)
	if !strings.HasSuffix(text, "%") {
		return 0, ErrEngineStatus
	}
	number, err := strconv.Atoi(strings.TrimSuffix(text, "%"))
	if err != nil || number < 0 || number > 100 {
		return 0, ErrEngineStatus
	}
	return number, nil
}

func decodeActiveAPIJSON(body io.Reader, out any, sentinel error) error {
	raw, err := io.ReadAll(io.LimitReader(body, engineMaxResponseBody+1))
	if err != nil {
		return fmt.Errorf("%w: read response", sentinel)
	}
	if len(raw) > engineMaxResponseBody {
		return fmt.Errorf("%w: response too large", sentinel)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("%w: invalid response", sentinel)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: invalid response", sentinel)
	}
	return nil
}

var _ EngineAdapter = (*ActiveAPIEngineAdapter)(nil)
var _ EngineResultFetcher = (*ActiveAPIEngineAdapter)(nil)
