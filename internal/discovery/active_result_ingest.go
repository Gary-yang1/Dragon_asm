//revive:disable:exported

package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

const (
	activeResultProvider = "sentinel"
	activeResultSource   = "active_engine"
	// Leave headroom below callbackMaxFacts for conservative per-target cost
	// estimates and JSON envelope overhead.
	activeResultBatchFactLimit = 1800
)

type activeResultIngestFunc func(
	ctx context.Context,
	run *TaskRun,
	payload callbackPayload,
) error

type activeResultPullSummary struct {
	FactCount       uint64
	TargetCount     int
	TotalTargets    int
	FinishedTargets int
}

// pullActiveRunResults drains every bounded result page before a terminal run is
// closed. Each page is materialized independently and idempotently; a later-page
// failure leaves the run running so the next poll safely replays earlier pages.
func (s *Service) pullActiveRunResults(
	ctx context.Context,
	run *TaskRun,
	engine EngineAdapter,
) (activeResultPullSummary, error) {
	fetcher, ok := engine.(EngineResultFetcher)
	if !ok {
		return activeResultPullSummary{}, ErrEngineResultUnsupported
	}
	if run == nil || run.ProjectID == 0 || run.ID == 0 ||
		!IsActiveTaskType(run.TaskType) ||
		!validActiveAPIIdentifier(strings.TrimSpace(run.EngineJobID), activeAPIMaxTaskIDLen) {
		return activeResultPullSummary{}, ErrEngineResult
	}
	if s.activeResultIngestFn == nil {
		return activeResultPullSummary{}, ErrCallbackIngestDB
	}

	hosts, err := s.projectHostClassifier(ctx, run.ProjectID)
	if err != nil {
		return activeResultPullSummary{}, err
	}
	now := s.nowFn()
	factKeys := make(map[string]struct{})
	targetKeys := make(map[string]struct{})
	summary := activeResultPullSummary{}
	maxPages := (activeAPIMaxTargets + activeAPIResultPageSize - 1) / activeAPIResultPageSize

	for pageNumber := 1; pageNumber <= maxPages; pageNumber++ {
		page, err := fetcher.FetchResultPage(
			ctx,
			run.EngineJobID,
			run.TaskType,
			pageNumber,
			activeAPIResultPageSize,
		)
		if err != nil {
			return activeResultPullSummary{}, err
		}
		if page.TaskID != run.EngineJobID ||
			page.Page != pageNumber ||
			page.PageSize != activeAPIResultPageSize ||
			page.TotalTargets <= 0 ||
			page.TotalTargets > activeAPIMaxTargets ||
			page.FinishedTargets < 0 ||
			page.FinishedTargets > page.TotalTargets {
			return activeResultPullSummary{}, ErrEngineResult
		}
		if pageNumber == 1 {
			summary.TotalTargets = page.TotalTargets
			summary.FinishedTargets = page.FinishedTargets
		} else if page.TotalTargets != summary.TotalTargets ||
			page.FinishedTargets != summary.FinishedTargets {
			return activeResultPullSummary{}, ErrEngineResult
		}

		batches, err := splitActiveResultPage(run.TaskType, page)
		if err != nil {
			return activeResultPullSummary{}, err
		}
		for _, batch := range batches {
			payload, pageTargetKeys, err := buildActiveResultPayload(run, batch, now, hosts)
			if err != nil {
				return activeResultPullSummary{}, err
			}
			if err := s.activeResultIngestFn(ctx, run, payload); err != nil {
				return activeResultPullSummary{}, err
			}
			for _, key := range pageTargetKeys {
				targetKeys[key] = struct{}{}
			}
			for _, fact := range payload.Assets {
				factKeys[ObservationKindAsset+"|"+fact.NaturalKey+"|"+fact.Provider] = struct{}{}
			}
			for _, fact := range payload.Relations {
				factKeys[ObservationKindRelation+"|"+fact.NaturalKey+"|"+fact.Provider] = struct{}{}
			}
			for _, fact := range payload.Exposures {
				factKeys[ObservationKindExposure+"|"+fact.NaturalKey+"|"+fact.Provider] = struct{}{}
			}
		}

		if pageNumber*activeAPIResultPageSize >= summary.TotalTargets {
			break
		}
	}

	summary.FactCount = uint64(len(factKeys))
	summary.TargetCount = len(targetKeys)
	return summary, nil
}

func splitActiveResultPage(taskType string, page EngineResultPage) ([]EngineResultPage, error) {
	base := EngineResultPage{
		TaskID: page.TaskID, Page: page.Page, PageSize: page.PageSize,
		TotalTargets: page.TotalTargets, FinishedTargets: page.FinishedTargets,
	}
	batches := make([]EngineResultPage, 0, 2)
	current := base
	currentCost := 0
	flush := func() {
		batches = append(batches, current)
		current = base
		currentCost = 0
	}

	switch taskType {
	case TaskTypePortProbe:
		if len(page.WebResults) != 0 {
			return nil, ErrEngineResult
		}
		for _, item := range page.PortResults {
			ports, err := parseActivePorts(item.Ports)
			if err != nil {
				return nil, err
			}
			cost := 1 + len(ports)
			if cost > activeResultBatchFactLimit {
				return nil, ErrEngineResult
			}
			if currentCost > 0 && currentCost+cost > activeResultBatchFactLimit {
				flush()
			}
			current.PortResults = append(current.PortResults, item)
			currentCost += cost
		}
	case TaskTypeWebProbe, TaskTypeFingerprint:
		if len(page.PortResults) != 0 {
			return nil, ErrEngineResult
		}
		for _, item := range page.WebResults {
			// Host asset + Web asset + contains relation + Web exposure, plus
			// one service exposure per fingerprint.
			cost := 4 + len(item.Fingerprints)
			if cost > activeResultBatchFactLimit {
				return nil, ErrEngineResult
			}
			if currentCost > 0 && currentCost+cost > activeResultBatchFactLimit {
				flush()
			}
			current.WebResults = append(current.WebResults, item)
			currentCost += cost
		}
	default:
		return nil, ErrEngineResultUnsupported
	}
	if currentCost > 0 || len(batches) == 0 {
		flush()
	}
	return batches, nil
}

func buildActiveResultPayload(
	run *TaskRun,
	page EngineResultPage,
	observedAt time.Time,
	hosts hostClassifier,
) (callbackPayload, []string, error) {
	if run == nil || run.ID == 0 || run.ProjectID == 0 || page.Page <= 0 ||
		page.TaskID != run.EngineJobID || observedAt.IsZero() {
		return callbackPayload{}, nil, ErrEngineResult
	}

	assets := make(map[string]callbackAssetV1)
	relations := make(map[string]callbackRelation)
	exposures := make(map[string]callbackExposureV1)
	targetKeys := make(map[string]struct{})
	evidenceRef := activeResultEvidenceRef(run.EngineJobID, page.Page)

	addAsset := func(normalized asset.Normalized, confidence uint8) callbackFactReference {
		naturalKey := normalized.Key
		if _, exists := assets[naturalKey]; !exists {
			assets[naturalKey] = callbackAssetV1{
				callbackFactMeta: activeFactMeta(
					naturalKey,
					observedAt,
					confidence,
					activeEvidenceHash("asset", naturalKey),
					evidenceRef,
				),
				AssetType:   normalized.Type,
				Value:       normalized.Value,
				DisplayName: normalized.Value,
				Attributes:  map[string]string{},
			}
		}
		return callbackFactReference{NaturalKey: naturalKey}
	}
	addRelation := func(
		from callbackFactReference,
		to callbackFactReference,
		relationType string,
		confidence uint8,
	) {
		naturalKey := activeNaturalKey(
			"relation",
			relationType,
			from.NaturalKey,
			to.NaturalKey,
		)
		relations[naturalKey] = callbackRelation{
			callbackFactMeta: activeFactMeta(
				naturalKey,
				observedAt,
				confidence,
				activeEvidenceHash(
					"relation",
					relationType,
					from.NaturalKey,
					to.NaturalKey,
				),
				evidenceRef,
			),
			RelationType: relationType,
			From:         from,
			To:           to,
		}
	}

	switch run.TaskType {
	case TaskTypePortProbe:
		if len(page.WebResults) != 0 {
			return callbackPayload{}, nil, ErrEngineResult
		}
		for _, item := range page.PortResults {
			normalized, err := asset.Normalize(asset.TypeIP, item.Target)
			if err != nil {
				return callbackPayload{}, nil, errors.Join(ErrEngineResult, err)
			}
			parent := addAsset(normalized, 100)
			targetKeys[normalized.Key] = struct{}{}
			ports, err := parseActivePorts(item.Ports)
			if err != nil {
				return callbackPayload{}, nil, err
			}
			for _, port := range ports {
				portText := strconv.Itoa(port)
				naturalKey := activeNaturalKey(
					"port",
					normalized.Key,
					"tcp",
					portText,
				)
				value := net.JoinHostPort(normalized.Value, portText)
				exposures[naturalKey] = callbackExposureV1{
					callbackFactMeta: activeFactMeta(
						naturalKey,
						observedAt,
						100,
						activeEvidenceHash("port", normalized.Key, "tcp", portText),
						evidenceRef,
					),
					Parent:       parent,
					ExposureType: "port",
					Name:         "TCP " + portText,
					Value:        value,
					Protocol:     "tcp",
					Port:         uint32(port), // #nosec G115 -- validated 1..65535
				}
			}
		}

	case TaskTypeWebProbe, TaskTypeFingerprint:
		if len(page.PortResults) != 0 {
			return callbackPayload{}, nil, ErrEngineResult
		}
		for _, item := range page.WebResults {
			safeURL, host, protocol, port, err := normalizeActiveWebTarget(item.Target, item.Port)
			if err != nil {
				return callbackPayload{}, nil, err
			}
			assetType := hosts.assetType(host)
			if net.ParseIP(host) != nil {
				assetType = asset.TypeIP
			}
			normalized, err := asset.Normalize(assetType, host)
			if err != nil {
				return callbackPayload{}, nil, errors.Join(ErrEngineResult, err)
			}
			hostParent := addAsset(normalized, 95)
			targetKeys["web:"+activeEvidenceHash("target", item.Target)] = struct{}{}
			webAsset, err := asset.Normalize(asset.TypeWeb, safeURL)
			if err != nil {
				return callbackPayload{}, nil, errors.Join(ErrEngineResult, err)
			}
			parent := addAsset(webAsset, 95)
			addRelation(hostParent, parent, "contains", 95)

			fingerprints, statusCode, title, err := normalizeActiveFingerprints(item.Fingerprints)
			if err != nil {
				return callbackPayload{}, nil, err
			}
			if title == "" {
				title = safeURL
			}
			if statusCode == "" {
				statusCode = "unknown"
			}
			fingerprintSummary := joinActiveFingerprintNames(fingerprints, 255)
			webNaturalKey := activeNaturalKey("web", normalized.Key, safeURL)
			exposures[webNaturalKey] = callbackExposureV1{
				Web: item.Web,
				callbackFactMeta: activeFactMeta(
					webNaturalKey,
					observedAt,
					95,
					activeEvidenceHash("web", safeURL, statusCode, title, fingerprintSummary),
					evidenceRef,
				),
				Parent:       parent,
				ExposureType: "web",
				Name:         title,
				Value:        statusCode,
				Protocol:     protocol,
				Port:         uint32(port), // #nosec G115 -- validated 1..65535
				URL:          safeURL,
				Fingerprint:  fingerprintSummary,
			}

			for _, fingerprint := range fingerprints {
				serviceNaturalKey := activeNaturalKey(
					"service",
					normalized.Key,
					protocol,
					strconv.Itoa(port),
					fingerprint,
				)
				exposures[serviceNaturalKey] = callbackExposureV1{
					callbackFactMeta: activeFactMeta(
						serviceNaturalKey,
						observedAt,
						90,
						activeEvidenceHash("service", safeURL, fingerprint),
						evidenceRef,
					),
					Parent:       parent,
					ExposureType: "service",
					Name:         fingerprint,
					Value:        fingerprint,
					Protocol:     protocol,
					Port:         uint32(port), // #nosec G115 -- validated 1..65535
					Service:      fingerprint,
					URL:          safeURL,
					Fingerprint:  fingerprint,
				}
			}
		}
	default:
		return callbackPayload{}, nil, ErrEngineResultUnsupported
	}

	assetKeys := make([]string, 0, len(assets))
	for key := range assets {
		assetKeys = append(assetKeys, key)
	}
	sort.Strings(assetKeys)
	assetFacts := make([]callbackAssetV1, 0, len(assetKeys))
	for _, key := range assetKeys {
		assetFacts = append(assetFacts, assets[key])
	}

	exposureKeys := make([]string, 0, len(exposures))
	for key := range exposures {
		exposureKeys = append(exposureKeys, key)
	}
	sort.Strings(exposureKeys)
	exposureFacts := make([]callbackExposureV1, 0, len(exposureKeys))
	for _, key := range exposureKeys {
		exposureFacts = append(exposureFacts, exposures[key])
	}

	relationKeys := make([]string, 0, len(relations))
	for key := range relations {
		relationKeys = append(relationKeys, key)
	}
	sort.Strings(relationKeys)
	relationFacts := make([]callbackRelation, 0, len(relationKeys))
	for _, key := range relationKeys {
		relationFacts = append(relationFacts, relations[key])
	}

	targetKeyList := make([]string, 0, len(targetKeys))
	for key := range targetKeys {
		targetKeyList = append(targetKeyList, key)
	}
	sort.Strings(targetKeyList)

	resultCount := len(assetFacts) + len(relationFacts) + len(exposureFacts)
	if resultCount > callbackMaxFacts {
		return callbackPayload{}, nil, ErrEngineResult
	}
	return callbackPayload{
		SchemaVersion:  callbackSchemaVersion,
		RunID:          run.ID,
		Seq:            uint64(page.Page), // #nosec G115 -- page is positive and bounded
		Phase:          CallbackPhaseProgress,
		Status:         TaskRunStatusRunning,
		ResultCount:    uint64(resultCount),
		ObservedAt:     observedAt,
		Assets:         assetFacts,
		Relations:      relationFacts,
		Exposures:      exposureFacts,
		ProviderErrors: []callbackProviderError{},
		ErrorSummary:   "",
	}, targetKeyList, nil
}

func (s *Service) ingestActiveResultPayload(
	ctx context.Context,
	run *TaskRun,
	payload callbackPayload,
) error {
	if s.db == nil {
		return ErrCallbackIngestDB
	}
	if run == nil ||
		run.ID != payload.RunID ||
		run.ProjectID == 0 ||
		payload.Seq == 0 ||
		payload.Assets == nil ||
		payload.Relations == nil ||
		payload.Exposures == nil ||
		payload.ProviderErrors == nil {
		return ErrEngineResult
	}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > callbackMaxBodyBytes {
		return ErrEngineResult
	}
	// raw is bounded by callbackMaxBodyBytes (4 MiB), so the conversion is safe.
	payloadSize := uint32(len(raw)) // #nosec G115
	callback := DiscoveryCallback{
		TenantID: run.TenantID, OrgID: run.OrgID, ProjectID: run.ProjectID,
		RunID: run.ID, Seq: payload.Seq, SchemaVersion: callbackSchemaVersion,
		Phase: payload.Phase, Status: payload.Status, ObservedAt: payload.ObservedAt,
		PayloadHash: callbackPayloadHash(raw), Payload: raw, PayloadSize: payloadSize,
		ResultCount: payload.ResultCount, ReceivedAt: payload.ObservedAt,
		IngestStatus: CallbackIngestProcessing,
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	q := dbgen.New(tx)
	locked, err := q.GetTaskRunForUpdate(ctx, dbgen.GetTaskRunForUpdateParams{
		ID: run.ID, ProjectID: run.ProjectID,
	})
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if locked.TenantID != run.TenantID ||
		locked.OrgID != run.OrgID ||
		locked.TaskType != run.TaskType ||
		locked.EngineJobID != run.EngineJobID {
		_ = tx.Rollback()
		return ErrEngineResult
	}
	if locked.Status != TaskRunStatusRunning {
		_ = tx.Rollback()
		return nil
	}
	if err := s.ingestCallbackFactsWith(ctx, tx, q, callback, payload); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func activeFactMeta(
	naturalKey string,
	observedAt time.Time,
	confidence uint8,
	evidenceHash string,
	evidenceRef string,
) callbackFactMeta {
	activeProbe := true
	return callbackFactMeta{
		NaturalKey:   naturalKey,
		Source:       activeResultSource,
		Provider:     activeResultProvider,
		ObservedAt:   observedAt,
		Confidence:   &confidence,
		ActiveProbe:  &activeProbe,
		EvidenceHash: evidenceHash,
		EvidenceRef:  evidenceRef,
	}
}

func parseActivePorts(raw string) ([]int, error) {
	raw = strings.ReplaceAll(strings.TrimSpace(raw), "，", ",")
	if raw == "" {
		return []int{}, nil
	}
	seen := make(map[int]struct{})
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, ErrEngineResult
		}
		seen[port] = struct{}{}
		if len(seen) > activeAPIMaxExpandedPorts {
			return nil, ErrEngineResult
		}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func normalizeActiveWebTarget(raw string, providerPort int) (string, string, string, int, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil ||
		(parsed.Scheme != httpScheme && parsed.Scheme != httpsScheme) ||
		parsed.Host == "" ||
		parsed.User != nil {
		return "", "", "", 0, ErrEngineResult
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	if containsActiveSensitiveMarker(parsed.Path) {
		parsed.Path = "/[REDACTED]"
		parsed.RawPath = ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return "", "", "", 0, ErrEngineResult
	}

	explicitPort := parsed.Port()
	switch {
	case explicitPort != "":
		parsed.Host = net.JoinHostPort(host, explicitPort)
	case net.ParseIP(host) != nil && strings.Contains(host, ":"):
		parsed.Host = "[" + host + "]"
	default:
		parsed.Host = host
	}

	port := 80
	if parsed.Scheme == httpsScheme {
		port = 443
	}
	if explicitPort != "" {
		port, err = strconv.Atoi(explicitPort)
		if err != nil || port < 1 || port > 65535 {
			return "", "", "", 0, ErrEngineResult
		}
	}
	if providerPort != 0 && providerPort != port {
		return "", "", "", 0, ErrEngineResult
	}
	safeURL := parsed.String()
	if len(safeURL) > 1024 {
		return "", "", "", 0, ErrEngineResult
	}
	return safeURL, host, parsed.Scheme, port, nil
}

func normalizeActiveFingerprints(
	items []EngineWebFingerprint,
) ([]string, string, string, error) {
	names := make(map[string]struct{})
	statusCode := ""
	title := ""
	for _, item := range items {
		name := sanitizeActiveResultText(item.Name, 128)
		if name != "" && name != "[REDACTED]" {
			names[name] = struct{}{}
		}
		normalized, err := normalizeActiveStatusCode(item.StatusCode)
		if err != nil {
			return nil, "", "", err
		}
		if statusCode == "" && normalized != "" {
			statusCode = normalized
		} else if normalized != "" && normalized != statusCode {
			return nil, "", "", ErrEngineResult
		}
		if title == "" {
			title = sanitizeActiveResultText(item.Title, 255)
		}
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, statusCode, title, nil
}

func normalizeActiveStatusCode(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) != 3 {
		return "", ErrEngineResult
	}
	statusCode, err := strconv.Atoi(raw)
	if err != nil || statusCode < 100 || statusCode > 599 {
		return "", ErrEngineResult
	}
	return raw, nil
}

func sanitizeActiveResultText(raw string, maxBytes int) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(raw))
	clean = strings.Join(strings.Fields(clean), " ")
	if clean == "" {
		return ""
	}
	if containsActiveSensitiveMarker(clean) {
		return "[REDACTED]"
	}
	return truncateActiveResultText(clean, maxBytes)
}

func containsActiveSensitiveMarker(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"authorization", "set-cookie", "cookie", "password", "passwd",
		"api_key", "api-key", "apikey", "token", "secret",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func truncateActiveResultText(value string, maxBytes int) string {
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
}

func joinActiveFingerprintNames(names []string, maxBytes int) string {
	var builder strings.Builder
	for _, name := range names {
		separator := ""
		if builder.Len() > 0 {
			separator = ","
		}
		if builder.Len()+len(separator)+len(name) > maxBytes {
			break
		}
		builder.WriteString(separator)
		builder.WriteString(name)
	}
	return builder.String()
}

func activeNaturalKey(prefix string, parts ...string) string {
	return callbackFactNaturalKey("", prefix, parts...)
}

func activeEvidenceHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func activeResultEvidenceRef(taskID string, page int) string {
	sum := sha256.Sum256([]byte(taskID))
	return fmt.Sprintf("active-result:%s:page:%d", hex.EncodeToString(sum[:8]), page)
}
