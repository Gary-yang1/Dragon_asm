package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MaxInheritedTargets bounds source records examined or confirmed in one batch.
const MaxInheritedTargets = 100

var (
	// ErrInheritanceInvalid identifies a malformed, foreign or incompatible selection.
	ErrInheritanceInvalid = errors.New("discovery: invalid inheritance selection")
	// ErrInheritanceNotReady rejects an unavailable source, evidence or authorization.
	ErrInheritanceNotReady = errors.New("discovery: inheritance source or parent authorization is unavailable")
	// ErrInheritanceScopeChanged requires review against the latest parent policy.
	ErrInheritanceScopeChanged = errors.New("discovery: parent authorization changed; refresh before continuing")
	// ErrInheritanceImmutable prevents modifying a previously captured target snapshot.
	ErrInheritanceImmutable = errors.New("discovery: inherited target snapshot cannot be edited; create a new continuation")
)

type inheritedObservationLister interface {
	ListInheritanceObservations(context.Context, uint64, uint64, uint64, int32) ([]*DiscoveryObservation, error)
}

// TargetInheritance lives in an immutable template config. Runs refer to that
// same snapshot; it is never forwarded as engine options or used to bypass Scope.
type TargetInheritance struct {
	ParentFingerprint string              `json:"parent_fingerprint"`
	SourceRunID       uint64              `json:"source_run_id"`
	ParentScopeID     uint64              `json:"parent_scope_id"`
	Evidence          []InheritedEvidence `json:"evidence"`
}

// InheritedEvidence pins one source observation and its normalized content.
type InheritedEvidence struct {
	ObservationID uint64    `json:"observation_id"`
	Hash          string    `json:"hash"`
	ObservedAt    time.Time `json:"observed_at"`
}

// DerivedTarget describes a source fact and its current authorization status.
type DerivedTarget struct {
	ObservationID uint64    `json:"observation_id"`
	TargetType    string    `json:"target_type"`
	Value         string    `json:"value"`
	Status        string    `json:"status"`
	Reason        string    `json:"reason"`
	Provider      string    `json:"provider"`
	ObservedAt    time.Time `json:"observed_at"`
	EvidenceHash  string    `json:"evidence_hash"`
}

// DerivedTargetPage exposes a bounded, cursor-paginated view under a parent scope.
type DerivedTargetPage struct {
	SourceRunID      uint64          `json:"source_run_id"`
	ParentScopeID    uint64          `json:"parent_scope_id"`
	ParentScopeName  string          `json:"parent_scope_name"`
	ScopeFingerprint string          `json:"scope_fingerprint"`
	ValidUntil       time.Time       `json:"valid_until"`
	ParentActive     bool            `json:"parent_active"`
	SourceComplete   bool            `json:"source_complete"`
	Items            []DerivedTarget `json:"items"`
	NextCursor       uint64          `json:"next_cursor"`
}

// CreateContinuationInput selects source evidence for an immutable next-step template.
type CreateContinuationInput struct {
	ProjectID        uint64
	SourceRunID      uint64
	TaskType         string
	ObservationIDs   []uint64
	ScopeFingerprint string
	ActorID          string
	Meta             AuditMeta
}

// AuthorizeDerivedInput records an explicit batch expansion of parent authorization.
type AuthorizeDerivedInput struct {
	ProjectID        uint64
	SourceRunID      uint64
	ObservationIDs   []uint64
	ScopeFingerprint string
	Reason           string
	ActorID          string
	Meta             AuditMeta
}

func inheritanceScopeFingerprint(scope *Scope) string {
	targets := append([]*ScopeTarget(nil), scope.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	raw, _ := json.Marshal(struct {
		ID          uint64
		Status      string
		From, Until time.Time
		Targets     []*ScopeTarget
	}{scope.ID, scope.Status, scope.ValidFrom, scope.ValidUntil, targets})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (s *Service) inheritanceSource(ctx context.Context, projectID, sourceRunID uint64) (*TaskRun, *Scope, error) {
	run, err := s.repo.GetTaskRun(ctx, projectID, sourceRunID)
	if err != nil {
		return nil, nil, err
	}
	if run.ProjectID != projectID {
		return nil, nil, ErrInheritanceInvalid
	}
	scope, err := s.GetScope(ctx, projectID, run.ScopeID)
	if err != nil {
		return nil, nil, err
	}
	if scope.ProjectID != projectID || scope.TenantID != run.TenantID || scope.OrgID != run.OrgID {
		return nil, nil, ErrInheritanceInvalid
	}
	return run, scope, nil
}
func (s *Service) parentAuthorizationActive(scope *Scope) bool {
	now := s.nowFn()
	return scope.Status == StatusActive && !now.Before(scope.ValidFrom) && !now.After(scope.ValidUntil)
}
func sourceRunComplete(run *TaskRun) bool {
	return run.Status == TaskRunStatusSuccess || run.Status == TaskRunStatusPartial
}

func observationTarget(observation *DiscoveryObservation) (string, string, bool) {
	if observation.Kind != ObservationKindAsset || observation.IngestStatus != ObservationStatusMaterialized {
		return "", "", false
	}
	var fact callbackAssetV1
	if json.Unmarshal(observation.NormalizedJSON, &fact) != nil {
		return "", "", false
	}
	kind := fact.AssetType
	switch kind {
	case "domain", "subdomain":
		kind = TargetTypeDomain
	case "ip":
		kind = TargetTypeIP
	case "web":
		kind = TargetTypeURL
	default:
		return "", "", false
	}
	value, err := normalizeTargetValue(kind, fact.Value)
	if err != nil {
		return kind, fact.Value, true
	}
	return kind, value, true
}
func (s *Service) derivedCandidate(scope *Scope, run *TaskRun, observation *DiscoveryObservation) (DerivedTarget, bool) {
	kind, value, ok := observationTarget(observation)
	if !ok || observation.ProjectID != run.ProjectID || observation.RunID != run.ID || observation.TenantID != run.TenantID || observation.OrgID != run.OrgID {
		return DerivedTarget{}, false
	}
	digest := sha256.Sum256(observation.NormalizedJSON)
	item := DerivedTarget{ObservationID: observation.ID, TargetType: kind, Value: value, Provider: observation.Provider, ObservedAt: observation.ObservedAt, EvidenceHash: hex.EncodeToString(digest[:]), Status: "pending", Reason: "尚未被父授权覆盖，需有授权管理权限的用户批量确认"}
	parsed, err := parseTypedTarget(kind, value)
	if err != nil {
		item.Status = "excluded"
		item.Reason = "目标格式无效或属于禁止访问的地址"
		return item, true
	}
	if !s.parentAuthorizationActive(scope) {
		item.Status = "blocked"
		item.Reason = "父授权未启用、尚未生效或已过期"
		return item, true
	}
	if !sourceRunComplete(run) {
		item.Status = "blocked"
		item.Reason = "来源任务尚未完成或未成功，不可用于后续执行"
		return item, true
	}
	switch scopeMatchDecision(scope.Targets, parsed) {
	case ReasonExcluded:
		item.Status = "excluded"
		item.Reason = "命中父授权排除规则"
	case reasonURLRestricted:
		item.Status = "excluded"
		item.Reason = "不符合父授权的 URL 主机、协议或端口规则，请在授权管理中调整"
	case ReasonAllowed:
		item.Status = "inherited"
		item.Reason = "沿用父授权的有效期和排除规则；下发前会再次检查"
	}
	return item, true
}

// ListDerivedTargets classifies materialized source facts without granting authorization.
func (s *Service) ListDerivedTargets(ctx context.Context, projectID, sourceRunID, afterID uint64) (*DerivedTargetPage, error) {
	run, scope, err := s.inheritanceSource(ctx, projectID, sourceRunID)
	if err != nil {
		return nil, err
	}
	lister, ok := s.repo.(inheritedObservationLister)
	if !ok {
		return nil, ErrInheritanceNotReady
	}
	observations, err := lister.ListInheritanceObservations(ctx, projectID, sourceRunID, afterID, MaxInheritedTargets+1)
	if err != nil {
		return nil, err
	}
	result := &DerivedTargetPage{SourceRunID: run.ID, ParentScopeID: scope.ID, ParentScopeName: scope.Name, ScopeFingerprint: inheritanceScopeFingerprint(scope), ValidUntil: scope.ValidUntil, ParentActive: s.parentAuthorizationActive(scope), SourceComplete: sourceRunComplete(run), Items: []DerivedTarget{}}
	if len(observations) > MaxInheritedTargets {
		observations = observations[:MaxInheritedTargets]
		result.NextCursor = observations[len(observations)-1].ID
	}
	for _, observation := range observations {
		if candidate, ok := s.derivedCandidate(scope, run, observation); ok {
			result.Items = append(result.Items, candidate)
		}
	}
	return result, nil
}
func (s *Service) selectedDerived(ctx context.Context, projectID, sourceRunID uint64, ids []uint64) (*Scope, []DerivedTarget, error) {
	if len(ids) == 0 || len(ids) > MaxInheritedTargets {
		return nil, nil, ErrInheritanceInvalid
	}
	run, scope, err := s.inheritanceSource(ctx, projectID, sourceRunID)
	if err != nil {
		return nil, nil, err
	}
	if !sourceRunComplete(run) || !s.parentAuthorizationActive(scope) {
		return nil, nil, ErrInheritanceNotReady
	}
	selected := make([]DerivedTarget, 0, len(ids))
	seen := map[uint64]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			return nil, nil, ErrInheritanceInvalid
		}
		seen[id] = true
		observation, err := s.repo.GetDiscoveryObservation(ctx, projectID, id)
		if err != nil {
			return nil, nil, err
		}
		candidate, ok := s.derivedCandidate(scope, run, observation)
		if !ok {
			return nil, nil, ErrInheritanceInvalid
		}
		selected = append(selected, candidate)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ObservationID < selected[j].ObservationID })
	return scope, selected, nil
}
func continuationTargetType(taskType string) string {
	switch taskType {
	case TaskTypeDNS, TaskTypePassiveIntel:
		return TargetTypeDomain
	case TaskTypePortProbe:
		return TargetTypeIP
	case TaskTypeWebProbe, TaskTypeFingerprint:
		return TargetTypeURL
	}
	return ""
}

// CreateContinuationTemplate materializes an immutable, evidence-linked input
// snapshot without starting a scan or granting any new authorization.
func (s *Service) CreateContinuationTemplate(ctx context.Context, in CreateContinuationInput) (*TaskTemplate, error) {
	if s.engineSettings != nil {
		scoped, err := s.withLatestSettings(ctx)
		if err != nil {
			return nil, err
		}
		return scoped.CreateContinuationTemplate(ctx, in)
	}
	kind := continuationTargetType(in.TaskType)
	if kind == "" || strings.TrimSpace(in.ActorID) == "" {
		return nil, ErrInheritanceInvalid
	}
	var result *TaskTemplate
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		if err := repo.LockProjectForScopeDefault(ctx, in.ProjectID); err != nil {
			return err
		}
		scoped := *s
		scoped.repo = repo
		scoped.db = nil
		scoped.auditSink = txAudit
		scope, selected, err := scoped.selectedDerived(ctx, in.ProjectID, in.SourceRunID, in.ObservationIDs)
		if err != nil {
			return err
		}
		if in.ScopeFingerprint != inheritanceScopeFingerprint(scope) {
			return ErrInheritanceScopeChanged
		}
		inheritance := &TargetInheritance{ParentFingerprint: inheritanceScopeFingerprint(scope), SourceRunID: in.SourceRunID, ParentScopeID: scope.ID, Evidence: []InheritedEvidence{}}
		targets := []map[string]string{}
		seen := map[string]bool{}
		for _, item := range selected {
			if item.Status != "inherited" || item.TargetType != kind {
				return ErrInheritanceNotReady
			}
			// Repeated observations of the same target must not multiply engine work.
			if seen[item.Value] {
				continue
			}
			seen[item.Value] = true
			targets = append(targets, map[string]string{"type": kind, "value": item.Value})
			inheritance.Evidence = append(inheritance.Evidence, InheritedEvidence{ObservationID: item.ObservationID, Hash: item.EvidenceHash, ObservedAt: item.ObservedAt})
		}
		options := map[string]any{}
		switch in.TaskType {
		case TaskTypeDNS:
			options = map[string]any{"profile": "resolve", "record_types": []string{"A", "AAAA", "CNAME"}, "max_results": 1000}
		case TaskTypePassiveIntel:
			options = map[string]any{"profile": "subdomain_passive", "sources": []string{"auto"}, "max_results": 1000}
		case TaskTypePortProbe:
			options = map[string]any{"ports": "80,443"}
		}
		raw, err := json.Marshal(map[string]any{"targets": targets, "options": options, "inheritance": inheritance})
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		name := fmt.Sprintf("接续 #%d · %s · %x", in.SourceRunID, in.TaskType, sum[:6])
		// The project lock also makes repeated clicks/retries reuse this snapshot.
		existing, err := repo.ListTaskTemplates(ctx, in.ProjectID)
		if err != nil {
			return err
		}
		for _, template := range existing {
			if template.ScopeID == scope.ID && template.TaskType == in.TaskType && hasInheritance(template.Config) && sameInheritanceConfig(template.Config, string(raw)) {
				if !template.Enabled {
					return ErrTemplateDisabled
				}
				result = template
				return nil
			}
			if template.Name == name {
				return ErrInheritanceInvalid
			}
		}

		rate := 200
		if IsActiveTaskType(in.TaskType) {
			rate = 50
		}
		result, err = scoped.CreateTaskTemplate(ctx, CreateTaskTemplateInput{ProjectID: in.ProjectID, TenantID: scope.TenantID, OrgID: scope.OrgID, ScopeID: scope.ID, Name: name, TaskType: in.TaskType, Config: string(raw), Enabled: true, TimeoutSeconds: 1800, Concurrency: 10, RateLimit: rate, RetryLimit: 3, ActorID: in.ActorID, Meta: in.Meta})
		return err
	})
	return result, err
}

// AuthorizeDerivedTargets is an explicit, permission-checked scope expansion.
// It only appends exact targets, never changes exclusions, dates or status.
func (s *Service) AuthorizeDerivedTargets(ctx context.Context, in AuthorizeDerivedInput) (*Scope, error) {
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || len(reason) > 500 || in.ActorID == "" {
		return nil, ErrInheritanceInvalid
	}
	var scopeID uint64
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		if err := repo.LockProjectForScopeDefault(ctx, in.ProjectID); err != nil {
			return err
		}
		scoped := *s
		scoped.repo = repo
		scoped.db = nil
		scoped.auditSink = txAudit
		before, selected, err := scoped.selectedDerived(ctx, in.ProjectID, in.SourceRunID, in.ObservationIDs)
		if err != nil {
			return err
		}
		scopeID = before.ID
		if in.ScopeFingerprint != inheritanceScopeFingerprint(before) {
			return ErrInheritanceScopeChanged
		}
		if len(before.Targets)+len(selected) > 1000 {
			return ErrInheritanceInvalid
		}
		seen := map[string]bool{}
		for _, item := range selected {
			if item.Status == "inherited" {
				continue
			}
			if item.Status != "pending" {
				return ErrInheritanceNotReady
			}
			key := item.TargetType + ":" + item.Value
			if seen[key] {
				continue
			}
			seen[key] = true
			if err := repo.InsertScopeTarget(ctx, InsertScopeTargetParams{TenantID: before.TenantID, OrgID: before.OrgID, ProjectID: in.ProjectID, ScopeID: before.ID, TargetType: item.TargetType, Value: item.Value, MatchMode: MatchModeInclude, CoverageMode: CoverageModeExact, ActorID: in.ActorID}); err != nil {
				return err
			}
		}
		if err := repo.UpdateScope(ctx, UpdateScopeParams{ScopeID: before.ID, TenantID: before.TenantID, OrgID: before.OrgID, ProjectID: in.ProjectID, Name: before.Name, Status: before.Status, AuthorizedBy: before.AuthorizedBy, ValidFrom: before.ValidFrom, ValidUntil: before.ValidUntil, IsDefault: before.IsDefault, ActorID: in.ActorID}); err != nil {
			return err
		}
		after, err := scoped.GetScope(ctx, in.ProjectID, before.ID)
		if err != nil {
			return err
		}
		meta := in.Meta
		meta.Reason = reason
		meta.SourceRunID = in.SourceRunID
		meta.SourceObservationIDs = append([]uint64(nil), in.ObservationIDs...)
		return s.recordAuditWithSink(ctx, txAudit, ActionScopeUpdate, before, after, in.ActorID, meta)
	})
	if err != nil {
		return nil, err
	}
	return s.GetScope(ctx, in.ProjectID, scopeID)
}

// validateInheritedSnapshot is called both when creating a run and immediately
// before dispatch. Mutable/deleted evidence and a changed parent fail closed.
func (s *Service) validateInheritedSnapshot(ctx context.Context, projectID, scopeID uint64, taskType, raw string) error {
	if !hasInheritance(raw) {
		return nil
	}
	var parsed struct {
		Inheritance *TargetInheritance `json:"inheritance"`
	}
	if json.Unmarshal([]byte(raw), &parsed) != nil {
		return ErrInvalidTaskConfig
	}
	if parsed.Inheritance == nil {
		return nil
	}
	provenance := parsed.Inheritance
	if !validEvidenceHash(provenance.ParentFingerprint) || provenance.ParentScopeID != scopeID || len(provenance.Evidence) == 0 || len(provenance.Evidence) > MaxInheritedTargets {
		return ErrInheritanceInvalid
	}
	ids := make([]uint64, len(provenance.Evidence))
	byID := map[uint64]InheritedEvidence{}
	for i, evidence := range provenance.Evidence {
		ids[i] = evidence.ObservationID
		byID[evidence.ObservationID] = evidence
	}
	parent, candidates, err := s.selectedDerived(ctx, projectID, provenance.SourceRunID, ids)
	if err != nil {
		return err
	}
	if parent.ID != scopeID {
		return ErrInheritanceInvalid
	}
	config, err := parseDispatchConfig(raw)
	if err != nil {
		return err
	}
	if len(config.Targets) != len(candidates) {
		return ErrInheritanceInvalid
	}
	expected := map[string]bool{}
	for _, candidate := range candidates {
		evidence := byID[candidate.ObservationID]
		if candidate.Status != "inherited" || candidate.TargetType != continuationTargetType(taskType) || candidate.EvidenceHash != evidence.Hash || !candidate.ObservedAt.Equal(evidence.ObservedAt) {
			return ErrInheritanceNotReady
		}
		expected[candidate.TargetType+":"+candidate.Value] = true
	}
	for _, target := range config.Targets {
		key := target.Type + ":" + target.Value
		if !expected[key] {
			return ErrInheritanceInvalid
		}
		delete(expected, key)
	}
	if len(expected) != 0 {
		return ErrInheritanceInvalid
	}
	return nil
}
func hasInheritance(raw string) bool {
	var parsed map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &parsed) != nil {
		return false
	}
	value, ok := parsed["inheritance"]
	return ok && string(value) != "null"
}

// MySQL JSON canonicalizes object order and whitespace when reading it back.
func sameInheritanceConfig(a, b string) bool {
	canonical := func(raw string) []byte {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) != nil {
			return nil
		}
		result, _ := json.Marshal(value)
		return result
	}
	left, right := canonical(a), canonical(b)
	return left != nil && right != nil && bytes.Equal(left, right)
}
