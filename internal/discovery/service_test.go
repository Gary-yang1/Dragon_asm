package discovery

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

type fakeRepo struct {
	scopes            map[uint64]map[uint64]*Scope
	targets           map[uint64]map[uint64][]*ScopeTarget
	clearCount        int
	nextScopeID       uint64
	nextTargetID      uint64
	templates         map[uint64]map[uint64]*TaskTemplate
	runs              map[uint64]map[uint64]*TaskRun
	callbacks         map[uint64]map[uint64]map[uint64]*DiscoveryCallback
	observations      map[uint64]map[uint64]*DiscoveryObservation
	nextTemplateID    uint64
	nextRunID         uint64
	nextObservationID uint64
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		scopes:       make(map[uint64]map[uint64]*Scope),
		targets:      make(map[uint64]map[uint64][]*ScopeTarget),
		templates:    make(map[uint64]map[uint64]*TaskTemplate),
		runs:         make(map[uint64]map[uint64]*TaskRun),
		callbacks:    make(map[uint64]map[uint64]map[uint64]*DiscoveryCallback),
		observations: make(map[uint64]map[uint64]*DiscoveryObservation),
	}
}

func (r *fakeRepo) CreateScope(ctx context.Context, in CreateScopeParams) (uint64, error) {
	_ = ctx
	r.nextScopeID++
	id := r.nextScopeID
	if _, ok := r.scopes[in.ProjectID]; !ok {
		r.scopes[in.ProjectID] = make(map[uint64]*Scope)
	}
	r.scopes[in.ProjectID][id] = &Scope{
		ID:           id,
		TenantID:     in.TenantID,
		OrgID:        in.OrgID,
		ProjectID:    in.ProjectID,
		Name:         in.Name,
		Status:       in.Status,
		AuthorizedBy: in.AuthorizedBy,
		ValidFrom:    in.ValidFrom,
		ValidUntil:   in.ValidUntil,
		CreatedBy:    in.ActorID,
		UpdatedBy:    in.ActorID,
		CreatedAt:    time.Time{},
		UpdatedAt:    time.Time{},
	}
	if _, ok := r.targets[in.ProjectID]; !ok {
		r.targets[in.ProjectID] = make(map[uint64][]*ScopeTarget)
	}
	return id, nil
}

func (r *fakeRepo) GetScope(ctx context.Context, projectID, scopeID uint64) (*Scope, error) {
	_ = ctx
	pp, ok := r.scopes[projectID]
	if !ok {
		return nil, ErrNotFound
	}
	scope, ok := pp[scopeID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *scope
	return &cp, nil
}

func (r *fakeRepo) ListScopes(ctx context.Context, projectID uint64) ([]*Scope, error) {
	_ = ctx
	pp, ok := r.scopes[projectID]
	if !ok {
		return nil, nil
	}
	out := make([]*Scope, 0, len(pp))
	for _, scope := range pp {
		cp := *scope
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakeRepo) UpdateScope(ctx context.Context, in UpdateScopeParams) error {
	_ = ctx
	scope, ok := r.scopes[in.ProjectID][in.ScopeID]
	if !ok {
		return ErrNotFound
	}
	scope.Name = in.Name
	scope.Status = in.Status
	scope.AuthorizedBy = in.AuthorizedBy
	scope.ValidFrom = in.ValidFrom
	scope.ValidUntil = in.ValidUntil
	scope.UpdatedBy = in.ActorID
	return nil
}

func (r *fakeRepo) DeactivateScope(ctx context.Context, projectID, scopeID uint64, actorID string, updatedAtNow func() time.Time) error {
	_ = ctx
	scope, ok := r.scopes[projectID][scopeID]
	if !ok {
		return ErrNotFound
	}
	scope.Status = StatusInactive
	scope.UpdatedBy = actorID
	scope.UpdatedAt = updatedAtNow()
	return nil
}

func (r *fakeRepo) InsertScopeTarget(ctx context.Context, in InsertScopeTargetParams) error {
	_ = ctx
	if _, ok := r.scopes[in.ProjectID][in.ScopeID]; !ok {
		return ErrNotFound
	}
	r.nextTargetID++
	target := &ScopeTarget{
		ID:         r.nextTargetID,
		TenantID:   in.TenantID,
		OrgID:      in.OrgID,
		ProjectID:  in.ProjectID,
		ScopeID:    in.ScopeID,
		TargetType: in.TargetType,
		MatchMode:  in.MatchMode,
		Value:      in.Value,
		CreatedBy:  in.ActorID,
		UpdatedBy:  in.ActorID,
	}
	r.targets[in.ProjectID][in.ScopeID] = append(r.targets[in.ProjectID][in.ScopeID], target)
	return nil
}

func (r *fakeRepo) ListScopeTargets(ctx context.Context, projectID, scopeID uint64) ([]*ScopeTarget, error) {
	_ = ctx
	targetsByProject, ok := r.targets[projectID]
	if !ok {
		return nil, nil
	}
	raw, ok := targetsByProject[scopeID]
	if !ok {
		return nil, nil
	}
	out := make([]*ScopeTarget, len(raw))
	copy(out, raw)
	return out, nil
}

func (r *fakeRepo) ClearScopeTargets(ctx context.Context, projectID, scopeID uint64, actorID string, deletedAt time.Time) error {
	_ = ctx
	_ = actorID
	_ = deletedAt
	r.clearCount++
	if _, ok := r.targets[projectID]; !ok {
		return ErrNotFound
	}
	r.targets[projectID][scopeID] = nil
	return nil
}

func (r *fakeRepo) CreateTaskTemplate(ctx context.Context, in CreateTaskTemplateParams) (uint64, error) {
	_ = ctx
	r.nextTemplateID++
	id := r.nextTemplateID
	if _, ok := r.templates[in.ProjectID]; !ok {
		r.templates[in.ProjectID] = make(map[uint64]*TaskTemplate)
	}
	r.templates[in.ProjectID][id] = &TaskTemplate{
		ID:             id,
		TenantID:       in.TenantID,
		OrgID:          in.OrgID,
		ProjectID:      in.ProjectID,
		ScopeID:        in.ScopeID,
		Name:           in.Name,
		TaskType:       in.TaskType,
		Config:         in.Config,
		Schedule:       in.Schedule,
		Enabled:        in.Enabled,
		TimeoutSeconds: in.TimeoutSeconds,
		RateLimit:      in.RateLimit,
		Concurrency:    in.Concurrency,
		RetryLimit:     in.RetryLimit,
		CreatedAt:      time.Time{},
		UpdatedAt:      time.Time{},
		CreatedBy:      in.ActorID,
		UpdatedBy:      in.ActorID,
	}
	return id, nil
}

func (r *fakeRepo) GetTaskTemplate(ctx context.Context, projectID, templateID uint64) (*TaskTemplate, error) {
	_ = ctx
	pp, ok := r.templates[projectID]
	if !ok {
		return nil, ErrNotFound
	}
	template, ok := pp[templateID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *template
	return &cp, nil
}

func (r *fakeRepo) ListTaskTemplates(ctx context.Context, projectID uint64) ([]*TaskTemplate, error) {
	_ = ctx
	pp, ok := r.templates[projectID]
	if !ok {
		return nil, nil
	}
	out := make([]*TaskTemplate, 0, len(pp))
	for _, template := range pp {
		cp := *template
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakeRepo) UpdateTaskTemplate(ctx context.Context, in UpdateTaskTemplateParams) error {
	_ = ctx
	template, ok := r.templates[in.ProjectID][in.TemplateID]
	if !ok {
		return ErrNotFound
	}
	template.Name = in.Name
	template.TaskType = in.TaskType
	template.Config = in.Config
	template.Schedule = in.Schedule
	template.TimeoutSeconds = in.TimeoutSeconds
	template.RateLimit = in.RateLimit
	template.Concurrency = in.Concurrency
	template.RetryLimit = in.RetryLimit
	template.UpdatedBy = in.ActorID
	return nil
}

func (r *fakeRepo) SetTaskTemplateEnabled(ctx context.Context, projectID, templateID uint64, enabled bool, actorID string) error {
	_ = ctx
	template, ok := r.templates[projectID][templateID]
	if !ok {
		return ErrNotFound
	}
	template.Enabled = enabled
	template.UpdatedBy = actorID
	return nil
}

func (r *fakeRepo) DeleteTaskTemplate(ctx context.Context, projectID, templateID uint64, actorID string) error {
	_ = ctx
	if _, ok := r.templates[projectID]; !ok {
		return ErrNotFound
	}
	template, ok := r.templates[projectID][templateID]
	if !ok {
		return ErrNotFound
	}
	template.DeletedAt = time.Now().UTC()
	template.UpdatedBy = actorID
	delete(r.templates[projectID], templateID)
	return nil
}

func (r *fakeRepo) CreateTaskRun(ctx context.Context, in CreateTaskRunParams) (uint64, error) {
	_ = ctx
	r.nextRunID++
	id := r.nextRunID
	if _, ok := r.runs[in.ProjectID]; !ok {
		r.runs[in.ProjectID] = make(map[uint64]*TaskRun)
	}
	r.runs[in.ProjectID][id] = &TaskRun{
		ID:                id,
		TenantID:          in.TenantID,
		OrgID:             in.OrgID,
		ProjectID:         in.ProjectID,
		TemplateID:        in.TemplateID,
		ScopeID:           in.ScopeID,
		TaskType:          in.TaskType,
		Status:            in.Status,
		Progress:          in.Progress,
		TimeoutSeconds:    in.TimeoutSeconds,
		RateLimit:         in.RateLimit,
		Concurrency:       in.Concurrency,
		RetryLimit:        in.RetryLimit,
		Attempt:           in.Attempt,
		EngineJobID:       in.EngineJobID,
		DispatchedAt:      in.DispatchedAt,
		LastCallbackAt:    in.LastCallbackAt,
		ResultCount:       in.ResultCount,
		CallbackSecretRef: in.CallbackSecretRef,
		StartedAt:         in.StartedAt,
		FinishedAt:        in.FinishedAt,
		ErrorSummary:      in.ErrorSummary,
		CreatedBy:         in.ActorID,
		UpdatedBy:         in.ActorID,
	}
	return id, nil
}

func (r *fakeRepo) GetTaskRun(ctx context.Context, projectID, runID uint64) (*TaskRun, error) {
	_ = ctx
	pp, ok := r.runs[projectID]
	if !ok {
		return nil, ErrNotFound
	}
	run, ok := pp[runID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *run
	return &cp, nil
}

func (r *fakeRepo) ListTaskRuns(ctx context.Context, projectID uint64) ([]*TaskRun, error) {
	_ = ctx
	pp, ok := r.runs[projectID]
	if !ok {
		return nil, nil
	}
	out := make([]*TaskRun, 0, len(pp))
	for _, run := range pp {
		cp := *run
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakeRepo) ListRunningRunsForReconcile(ctx context.Context, limit int32) ([]*TaskRun, error) {
	_ = ctx
	if limit <= 0 {
		limit = 100
	}
	out := make([]*TaskRun, 0)
	for _, pp := range r.runs {
		for _, run := range pp {
			if run.Status == TaskRunStatusRunning && run.EngineJobID != "" && !run.DispatchedAt.IsZero() {
				cp := *run
				out = append(out, &cp)
				if int32(len(out)) >= limit {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

func (r *fakeRepo) MarkRunRunning(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, startedAt time.Time) error {
	_ = ctx
	_ = actorID
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != fromStatus {
		return ErrInvalidRunTransition
	}
	run.Status = TaskRunStatusRunning
	run.StartedAt = startedAt
	run.UpdatedBy = actorID
	return nil
}

func (r *fakeRepo) MarkRunDispatched(ctx context.Context, projectID, runID uint64, actorID, fromStatus, engineJobID string, now time.Time) error {
	_ = ctx
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != fromStatus {
		return ErrInvalidRunTransition
	}
	run.Status = TaskRunStatusRunning
	run.Progress = 0
	run.EngineJobID = engineJobID
	run.DispatchedAt = now
	run.StartedAt = now
	run.UpdatedBy = actorID
	return nil
}

func (r *fakeRepo) MarkRunDispatchFailed(ctx context.Context, projectID, runID uint64, actorID, fromStatus, errorSummary string, now time.Time) error {
	_ = ctx
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != fromStatus {
		return ErrInvalidRunTransition
	}
	run.Status = TaskRunStatusFailed
	run.Progress = 0
	run.ErrorSummary = errorSummary
	run.FinishedAt = now
	run.UpdatedBy = actorID
	return nil
}

func (r *fakeRepo) MarkRunSucceeded(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, resultCount uint64, now time.Time) error {
	_ = ctx
	_ = now
	_ = actorID
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != fromStatus {
		return ErrInvalidRunTransition
	}
	run.Status = TaskRunStatusSuccess
	run.Progress = 100
	run.ResultCount = resultCount
	run.ErrorSummary = ""
	run.FinishedAt = now
	run.UpdatedBy = actorID
	return nil
}

func (r *fakeRepo) MarkRunPartialSuccess(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, resultCount uint64, now time.Time) error {
	_ = ctx
	_ = now
	_ = actorID
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != fromStatus {
		return ErrInvalidRunTransition
	}
	run.Status = TaskRunStatusPartial
	run.Progress = 100
	run.ResultCount = resultCount
	run.ErrorSummary = ""
	run.FinishedAt = now
	run.UpdatedBy = actorID
	return nil
}

func (r *fakeRepo) MarkRunFailed(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, errorSummary string, resultCount uint64, now time.Time) error {
	_ = ctx
	_ = actorID
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != fromStatus {
		return ErrInvalidRunTransition
	}
	run.Status = TaskRunStatusFailed
	run.Progress = 0
	run.ResultCount = resultCount
	run.ErrorSummary = errorSummary
	run.FinishedAt = now
	run.UpdatedBy = actorID
	return nil
}

func (r *fakeRepo) MarkRunCancelled(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, errorSummary string, now time.Time) error {
	_ = ctx
	_ = actorID
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != fromStatus {
		return ErrInvalidRunTransition
	}
	run.Status = TaskRunStatusCancelled
	run.ErrorSummary = errorSummary
	run.Progress = 0
	run.FinishedAt = now
	run.UpdatedBy = actorID
	return nil
}

func (r *fakeRepo) IncrementRunAttempt(ctx context.Context, projectID, runID uint64, actorID string, now time.Time) error {
	_ = ctx
	_ = now
	_ = actorID
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	run.Attempt++
	return nil
}

func (r *fakeRepo) MarkRunCallbackReceived(ctx context.Context, projectID, runID uint64, actorID string, resultCount uint64, now time.Time) error {
	_ = ctx
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != TaskRunStatusRunning {
		return ErrInvalidRunTransition
	}
	run.LastCallbackAt = now
	run.ResultCount += resultCount
	run.UpdatedBy = actorID
	return nil
}

func (r *fakeRepo) InsertDiscoveryCallback(ctx context.Context, in DiscoveryCallback) (bool, error) {
	_ = ctx
	if _, ok := r.callbacks[in.ProjectID]; !ok {
		r.callbacks[in.ProjectID] = make(map[uint64]map[uint64]*DiscoveryCallback)
	}
	if _, ok := r.callbacks[in.ProjectID][in.RunID]; !ok {
		r.callbacks[in.ProjectID][in.RunID] = make(map[uint64]*DiscoveryCallback)
	}
	if _, ok := r.callbacks[in.ProjectID][in.RunID][in.Seq]; ok {
		return false, nil
	}
	cp := in
	r.callbacks[in.ProjectID][in.RunID][in.Seq] = &cp
	return true, nil
}

func (r *fakeRepo) GetDiscoveryCallback(ctx context.Context, projectID, runID, seq uint64) (*DiscoveryCallback, error) {
	_ = ctx
	runs, ok := r.callbacks[projectID]
	if !ok {
		return nil, ErrNotFound
	}
	callbacks, ok := runs[runID]
	if !ok {
		return nil, ErrNotFound
	}
	cb, ok := callbacks[seq]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *cb
	cp.Payload = append([]byte(nil), cb.Payload...)
	return &cp, nil
}

func (r *fakeRepo) ListPendingDiscoveryCallbacks(ctx context.Context, limit int32) ([]*DiscoveryCallback, error) {
	_ = ctx
	items := make([]*DiscoveryCallback, 0)
	for _, runs := range r.callbacks {
		for _, callbacks := range runs {
			for _, cb := range callbacks {
				if cb.IngestStatus == CallbackIngestPending {
					cp := *cb
					cp.Payload = append([]byte(nil), cb.Payload...)
					items = append(items, &cp)
					if int32(len(items)) == limit {
						return items, nil
					}
				}
			}
		}
	}
	return items, nil
}

func (r *fakeRepo) MarkDiscoveryCallbackEnqueued(ctx context.Context, projectID, runID, seq uint64, enqueuedAt time.Time) error {
	_ = ctx
	cb, ok := r.callbacks[projectID][runID][seq]
	if !ok {
		return ErrNotFound
	}
	cb.EnqueuedAt = enqueuedAt
	return nil
}

func (r *fakeRepo) MarkDiscoveryCallbackProcessing(ctx context.Context, projectID, runID, seq uint64) (bool, error) {
	_ = ctx
	cb, err := r.GetDiscoveryCallback(context.Background(), projectID, runID, seq)
	if err != nil {
		return false, err
	}
	if cb.IngestStatus != CallbackIngestPending && cb.IngestStatus != CallbackIngestFailed {
		return false, nil
	}
	stored := r.callbacks[projectID][runID][seq]
	stored.IngestStatus = CallbackIngestProcessing
	stored.IngestAttempt++
	stored.IngestError = ""
	return true, nil
}

func (r *fakeRepo) MarkDiscoveryCallbackProcessed(ctx context.Context, projectID, runID, seq uint64, processedAt time.Time) (bool, error) {
	_ = ctx
	cb, ok := r.callbacks[projectID][runID][seq]
	if !ok || cb.IngestStatus != CallbackIngestProcessing {
		return false, nil
	}
	cb.IngestStatus = CallbackIngestProcessed
	cb.ProcessedAt = processedAt
	cb.IngestError = ""
	return true, nil
}

func (r *fakeRepo) MarkDiscoveryCallbackFailed(ctx context.Context, projectID, runID, seq uint64, summary string) error {
	_ = ctx
	cb, ok := r.callbacks[projectID][runID][seq]
	if !ok {
		return ErrNotFound
	}
	if cb.IngestStatus == CallbackIngestProcessing {
		cb.IngestStatus = CallbackIngestFailed
		cb.IngestError = summary
	}
	return nil
}

func (r *fakeRepo) ListDiscoveryCallbacksForRunForUpdate(ctx context.Context, projectID, runID uint64) ([]*DiscoveryCallback, error) {
	_ = ctx
	callbacks, ok := r.callbacks[projectID][runID]
	if !ok {
		return []*DiscoveryCallback{}, nil
	}
	items := make([]*DiscoveryCallback, 0, len(callbacks))
	for seq := uint64(1); seq <= uint64(len(callbacks)); seq++ { // #nosec G115 -- bounded by in-memory test map size
		if cb, ok := callbacks[seq]; ok {
			cp := *cb
			cp.Payload = append([]byte(nil), cb.Payload...)
			items = append(items, &cp)
		}
	}
	return items, nil
}

func (r *fakeRepo) UpsertDiscoveryObservation(ctx context.Context, in DiscoveryObservation) (*DiscoveryObservation, error) {
	_ = ctx
	normalized, err := normalizeDiscoveryObservation(in)
	if err != nil {
		return nil, err
	}
	if _, ok := r.observations[normalized.ProjectID]; !ok {
		r.observations[normalized.ProjectID] = make(map[uint64]*DiscoveryObservation)
	}
	for _, existing := range r.observations[normalized.ProjectID] {
		if existing.RunID == normalized.RunID && existing.Kind == normalized.Kind && existing.NaturalKey == normalized.NaturalKey && existing.Provider == normalized.Provider {
			normalized.ID = existing.ID
			cp := normalized
			r.observations[normalized.ProjectID][existing.ID] = &cp
			return &cp, nil
		}
	}
	r.nextObservationID++
	normalized.ID = r.nextObservationID
	cp := normalized
	r.observations[normalized.ProjectID][normalized.ID] = &cp
	return &cp, nil
}

func (r *fakeRepo) GetDiscoveryObservation(ctx context.Context, projectID, observationID uint64) (*DiscoveryObservation, error) {
	_ = ctx
	item, ok := r.observations[projectID][observationID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *item
	cp.NormalizedJSON = append([]byte(nil), item.NormalizedJSON...)
	return &cp, nil
}

func (r *fakeRepo) ListDiscoveryObservationsByRun(ctx context.Context, projectID, runID, seq uint64) ([]*DiscoveryObservation, error) {
	_ = ctx
	items := make([]*DiscoveryObservation, 0)
	for _, item := range r.observations[projectID] {
		if item.RunID == runID && (seq == 0 || item.Seq == seq) {
			cp := *item
			items = append(items, &cp)
		}
	}
	return items, nil
}

func (r *fakeRepo) ListDiscoveryObservationsByNaturalKey(ctx context.Context, projectID uint64, kind, naturalKey string) ([]*DiscoveryObservation, error) {
	_ = ctx
	kind = strings.ToLower(strings.TrimSpace(kind))
	naturalKey = strings.ToLower(strings.TrimSpace(naturalKey))
	items := make([]*DiscoveryObservation, 0)
	for _, item := range r.observations[projectID] {
		if item.Kind == kind && item.NaturalKey == naturalKey {
			cp := *item
			items = append(items, &cp)
		}
	}
	return items, nil
}

func (r *fakeRepo) MarkDiscoveryObservationMaterialized(ctx context.Context, projectID, observationID uint64) error {
	_ = ctx
	item, ok := r.observations[projectID][observationID]
	if !ok {
		return ErrNotFound
	}
	item.IngestStatus = ObservationStatusMaterialized
	item.IngestError = ""
	return nil
}

func (r *fakeRepo) ApplyDiscoveryObservationLifecycle(ctx context.Context, projectID, runID uint64, capability string, missThreshold uint32, allowMiss bool, actorID string, now time.Time) error {
	_ = ctx
	_ = projectID
	_ = runID
	_ = capability
	_ = missThreshold
	_ = allowMiss
	_ = actorID
	_ = now
	return nil
}

type fakeAudit struct {
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	f.events = append(f.events, e)
	return nil
}

type fakeCallbackEnqueuer struct {
	calls int
	items []DiscoveryCallback
	err   error
}

func (f *fakeCallbackEnqueuer) EnqueueDiscoveryCallback(_ context.Context, cb DiscoveryCallback) error {
	if f.err != nil {
		return f.err
	}
	f.calls++
	f.items = append(f.items, cb)
	return nil
}

type fakeEngine struct {
	dispatchCalls int
	cancelCalls   int
	statusCalls   int
	jobs          []ScanJob
	ids           []string
	errs          []error
	cancelErr     error
	statuses      []EngineJobStatus
	statusErr     error
}

func (f *fakeEngine) Dispatch(_ context.Context, job ScanJob) (string, error) {
	f.dispatchCalls++
	f.jobs = append(f.jobs, job)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if err != nil {
			return "", err
		}
	}
	if len(f.ids) > 0 {
		id := f.ids[0]
		f.ids = f.ids[1:]
		return id, nil
	}
	return "engine-job-1", nil
}

func (f *fakeEngine) Cancel(_ context.Context, _ string) error {
	f.cancelCalls++
	return f.cancelErr
}

func (f *fakeEngine) Status(_ context.Context, _ string) (EngineJobStatus, error) {
	f.statusCalls++
	if f.statusErr != nil {
		return EngineJobStatus{}, f.statusErr
	}
	if len(f.statuses) > 0 {
		status := f.statuses[0]
		f.statuses = f.statuses[1:]
		return status, nil
	}
	return EngineJobStatus{Status: EngineJobStatusRunning}, nil
}

func TestCreateScopeWritesAuditAndNormalizesTargets(t *testing.T) {
	repo := newFakeRepo()
	auditSink := &fakeAudit{}
	now := time.Now().UTC()
	svc := NewService(repo, WithAuditSink(auditSink), WithNow(func() time.Time { return now }))

	out, err := svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    5,
		Name:         "Scope A",
		AuthorizedBy: "alice",
		Status:       StatusActive,
		ValidFrom:    now.Add(-time.Minute),
		ValidUntil:   now.Add(time.Hour),
		ActorID:      "alice",
		Targets: []ScopeTargetInput{
			{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: " Example.COM. "},
			{TargetType: TargetTypeURL, MatchMode: MatchModeInclude, Value: "https://API.EXAMPLE.COM:443/path"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), out.ID)
	assert.Len(t, out.Targets, 2)
	assert.Equal(t, "example.com", out.Targets[0].Value)
	assert.Equal(t, "https://api.example.com:443", out.Targets[1].Value)
	assert.Len(t, auditSink.events, 1)
	assert.Equal(t, ActionScopeCreate, auditSink.events[0].Action)
	assert.Equal(t, ResourceTypeScope, auditSink.events[0].ResourceType)
	assert.Equal(t, "1", auditSink.events[0].ResourceID)
}

func TestCreateScopeDefaultsToInactive(t *testing.T) {
	repo := newFakeRepo()
	now := time.Now().UTC()
	svc := NewService(repo)

	out, err := svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    15,
		Name:         "default-inactive",
		AuthorizedBy: "alice",
		Status:       "",
		ValidFrom:    now.Add(-time.Minute),
		ValidUntil:   now.Add(time.Minute),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, StatusInactive, out.Status)
}

func TestUpdateScopeReplacesTargetsAndAudits(t *testing.T) {
	repo := newFakeRepo()
	auditSink := &fakeAudit{}
	now := time.Now().UTC()
	svc := NewService(repo, WithAuditSink(auditSink), WithNow(func() time.Time { return now }))

	base, err := svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    6,
		Name:         "Old",
		AuthorizedBy: "alice",
		Status:       StatusActive,
		ValidFrom:    now.Add(-time.Minute),
		ValidUntil:   now.Add(time.Hour),
		ActorID:      "alice",
		Targets: []ScopeTargetInput{
			{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "old.example.com"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, base)

	newName := "New"
	newStatus := StatusInactive
	t.Run("replace", func(t *testing.T) {
		updated, err := svc.UpdateScope(context.Background(), UpdateScopeInput{
			ScopeID:      base.ID,
			TenantID:     "t1",
			OrgID:        "o1",
			ProjectID:    6,
			Name:         &newName,
			AuthorizedBy: nil,
			ValidFrom:    nil,
			ValidUntil:   nil,
			Status:       &newStatus,
			ActorID:      "alice",
			Targets: &[]ScopeTargetInput{
				{TargetType: TargetTypeIP, MatchMode: MatchModeInclude, Value: "1.1.1.1"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, newName, updated.Name)
		assert.Equal(t, StatusInactive, updated.Status)
		assert.Len(t, updated.Targets, 1)
		assert.Equal(t, "1.1.1.1", updated.Targets[0].Value)
		assert.Equal(t, 1, repo.clearCount)
		require.Len(t, auditSink.events, 2)
		assert.Equal(t, ActionScopeUpdate, auditSink.events[1].Action)
		assert.Equal(t, "alice", auditSink.events[1].ActorID)
	})
}

func TestUpdateScopeRejectsInvalidAuthorizedBy(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	base, err := svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    14,
		Name:         "policy",
		AuthorizedBy: "alice",
		Status:       StatusActive,
		ValidFrom:    time.Now().Add(-time.Hour),
		ValidUntil:   time.Now().Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)

	empty := "   "
	_, err = svc.UpdateScope(context.Background(), UpdateScopeInput{
		ScopeID:      base.ID,
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    14,
		AuthorizedBy: &empty,
		ActorID:      "alice",
	})
	assert.ErrorIs(t, err, ErrInvalidAuthorizedBy)
}

func TestDeactivateScopeWritesAudit(t *testing.T) {
	repo := newFakeRepo()
	auditSink := &fakeAudit{}
	now := time.Now().UTC()
	svc := NewService(repo, WithAuditSink(auditSink), WithNow(func() time.Time { return now }))

	scope, err := svc.CreateScope(context.Background(), CreateScopeInput{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    7,
		Name:         "ToDisable",
		AuthorizedBy: "alice",
		Status:       StatusActive,
		ValidFrom:    now.Add(-time.Minute),
		ValidUntil:   now.Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, StatusActive, scope.Status)

	err = svc.DeactivateScope(context.Background(), DeactivateScopeInput{
		ScopeID:   scope.ID,
		ProjectID: 7,
		ActorID:   "alice",
		Meta:      AuditMeta{IP: "10.0.0.1"},
	})
	require.NoError(t, err)

	after, err := svc.GetScope(context.Background(), 7, scope.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusInactive, after.Status)

	require.Len(t, auditSink.events, 2)
	assert.Equal(t, ActionScopeDeactivate, auditSink.events[1].Action)
	assert.Equal(t, "10.0.0.1", auditSink.events[1].IP)
}

func TestIsTargetAllowedMatchesAndBlocks(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }))

	scopeID, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    8,
		Name:         "policy",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		ValidUntil:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		ActorID:      "alice",
	})
	require.NoError(t, err)

	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 8, ScopeID: scopeID,
		TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com", ActorID: "alice",
	}))
	// Exclude the same candidate with a different target type to assert precedence.
	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 8, ScopeID: scopeID,
		TargetType: TargetTypeURL, MatchMode: MatchModeExclude, Value: "https://example.com/path",
		ActorID: "alice",
	}))

	ok, reason, err := svc.IsTargetAllowed(context.Background(), 8, scopeID, "https://example.com/path")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, ReasonExcluded, reason)

	ok, reason, err = svc.IsTargetAllowed(context.Background(), 8, scopeID, "https://not-included.com")
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, ReasonNoMatch, reason)
}

func TestIsTargetAllowedScopeWindowAndCrossProject(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	repo := newFakeRepo()
	auditSink := &fakeAudit{}
	svc := NewService(repo, WithNow(func() time.Time { return base }), WithAuditSink(auditSink))
	scopeID, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    9,
		Name:         "inactive-policy",
		Status:       StatusInactive,
		AuthorizedBy: "alice",
		ValidFrom:    base.Add(-time.Hour),
		ValidUntil:   base.Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 9, ScopeID: scopeID,
		TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com", ActorID: "alice",
	}))

	ok, reason, err := svc.IsTargetAllowed(context.Background(), 9, scopeID, "example.com")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, ReasonScopeInactive, reason)

	// Future scope windows are rejected.
	futureScopeID, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    9,
		Name:         "future",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    base.Add(time.Hour),
		ValidUntil:   base.Add(2 * time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 9, ScopeID: futureScopeID,
		TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com", ActorID: "alice",
	}))
	ok, reason, err = svc.IsTargetAllowed(context.Background(), 9, futureScopeID, "example.com")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, ReasonNotStarted, reason)

	// Expired scope rejected.
	expiredScopeID, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    9,
		Name:         "expired",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    base.Add(-2 * time.Hour),
		ValidUntil:   base.Add(-time.Minute),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 9, ScopeID: expiredScopeID,
		TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com", ActorID: "alice",
	}))
	ok, reason, err = svc.IsTargetAllowed(context.Background(), 9, expiredScopeID, "example.com")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, ReasonScopeExpired, reason)

	ok, reason, err = svc.IsTargetAllowed(context.Background(), 10, scopeID, "example.com")
	assert.False(t, ok)
	assert.Equal(t, ReasonScopeNotFound, reason)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestIsTargetAllowedDangerousTarget(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }))
	scopeID, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    11,
		Name:         "policy",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		ValidUntil:   time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 11, ScopeID: scopeID,
		TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com", ActorID: "alice",
	}))

	ok, reason, err := svc.IsTargetAllowed(context.Background(), 11, scopeID, "http://localhost/")
	assert.False(t, ok)
	assert.Equal(t, ReasonDangerous, reason)
	assert.ErrorIs(t, err, ErrDangerousTarget)
	assert.False(t, ok, "dangerous candidate must not be allowed")
}

func TestServiceListScopesProjectIsolation(t *testing.T) {
	repo := newFakeRepo()
	projectOneScopeID, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "a",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Time{},
		ValidUntil:   time.Time{},
		ActorID:      "alice",
	})
	require.NoError(t, err)
	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, ScopeID: projectOneScopeID,
		TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "project-one.example", ActorID: "alice",
	}))
	projectTwoScopeID, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    2,
		Name:         "b",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Time{},
		ValidUntil:   time.Time{},
		ActorID:      "alice",
	})
	require.NoError(t, err)
	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 2, ScopeID: projectTwoScopeID,
		TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "project-two.example", ActorID: "alice",
	}))

	svc := NewService(repo)
	scopes, err := svc.ListScopes(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, scopes, 1)
	assert.Equal(t, uint64(1), scopes[0].ID)
	assert.Equal(t, uint64(1), scopes[0].ProjectID)
	require.Len(t, scopes[0].Targets, 1)
	assert.Equal(t, "project-one.example", scopes[0].Targets[0].Value)
}

func TestServiceListScopesRejectsInvalidProjectID(t *testing.T) {
	svc := NewService(newFakeRepo())
	_, err := svc.ListScopes(context.Background(), 0)
	assert.ErrorIs(t, err, ErrInvalidProjectID)
}

func TestServiceGetScopeReturnsProjectScopedScopeAndTargets(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	id, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    12,
		Name:         "policy",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil:   time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID: "t1", OrgID: "o1", ProjectID: 12, ScopeID: id, TargetType: TargetTypeDomain,
		MatchMode: MatchModeInclude, Value: "example.com", ActorID: "alice",
	}))

	scope, err := svc.GetScope(context.Background(), 12, id)
	require.NoError(t, err)
	assert.Equal(t, id, scope.ID)
	assert.Len(t, scope.Targets, 1)
	assert.Equal(t, TargetTypeDomain, scope.Targets[0].TargetType)

	_, err = svc.GetScope(context.Background(), 13, id)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestCreateTaskTemplateValidatesAndPersists(t *testing.T) {
	repo := newFakeRepo()
	auditSink := &fakeAudit{}
	_, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Now().Add(-time.Minute),
		ValidUntil:   time.Now().Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)

	svc := NewService(repo, WithAuditSink(auditSink))
	out, err := svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      1,
		ScopeID:        1,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         `{"target":"example.com"}`,
		Schedule:       "*/10 * * * *",
		Enabled:        true,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, "template", out.Name)
	require.Len(t, auditSink.events, 1)
	assert.Equal(t, ActionTemplateCreate, auditSink.events[0].Action)
}

func TestCreateTaskTemplateRejectsSensitiveConfig(t *testing.T) {
	repo := newFakeRepo()
	_, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Now().Add(-time.Minute),
		ValidUntil:   time.Now().Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)

	svc := NewService(repo)
	_, err = svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      1,
		ScopeID:        1,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         `{"password":"super"}`,
		Schedule:       "*/10 * * * *",
		Enabled:        true,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	assert.ErrorIs(t, err, ErrInvalidTaskConfig)
}

func TestCreateTaskTemplateEmptyConfigDefaultsToEmptyObject(t *testing.T) {
	repo := newFakeRepo()
	_, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Now().Add(-time.Minute),
		ValidUntil:   time.Now().Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)

	svc := NewService(repo)
	out, err := svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      1,
		ScopeID:        1,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         "",
		Enabled:        true,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, "{}", out.Config)
}

func TestUpdateTaskTemplateEmptyConfigDefaultsToEmptyObject(t *testing.T) {
	repo := newFakeRepo()
	_, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Now().Add(-time.Minute),
		ValidUntil:   time.Now().Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)

	svc := NewService(repo)
	created, err := svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      1,
		ScopeID:        1,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         `{"target":"example.com"}`,
		Enabled:        true,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	require.NoError(t, err)

	empty := ""
	updated, err := svc.UpdateTaskTemplate(context.Background(), UpdateTaskTemplateInput{
		TemplateID: created.ID,
		ProjectID:  1,
		Config:     &empty,
		ActorID:    "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, "{}", updated.Config)
}

func TestCreateTaskRunUsesTemplateSnapshot(t *testing.T) {
	repo := newFakeRepo()
	_, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Now().Add(-time.Minute),
		ValidUntil:   time.Now().Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)

	svc := NewService(repo, WithCallbackSecretRef("baiyan-primary"))
	template, err := svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      1,
		ScopeID:        1,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         `{"target":"example.com"}`,
		Enabled:        true,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	require.NoError(t, err)

	run, err := svc.CreateTaskRun(context.Background(), CreateTaskRunInput{
		TemplateID: template.ID,
		ProjectID:  1,
		ActorID:    "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, template.ScopeID, run.ScopeID)
	assert.Equal(t, template.TaskType, run.TaskType)
	assert.Equal(t, TaskRunStatusPending, run.Status)
	assert.Equal(t, "baiyan-primary", run.CallbackSecretRef)
}

func TestCreateTaskRunRejectsDisabledTemplate(t *testing.T) {
	repo := newFakeRepo()
	_, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Now().Add(-time.Minute),
		ValidUntil:   time.Now().Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)

	svc := NewService(repo)
	template, err := svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      1,
		ScopeID:        1,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         `{"target":"example.com"}`,
		Enabled:        false,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	require.NoError(t, err)

	_, err = svc.CreateTaskRun(context.Background(), CreateTaskRunInput{
		TemplateID: template.ID,
		ProjectID:  1,
		ActorID:    "alice",
	})
	assert.ErrorIs(t, err, ErrTemplateDisabled)
}

func TestTaskRunTransitionMachineEnforced(t *testing.T) {
	repo := newFakeRepo()
	_, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Now().Add(-time.Minute),
		ValidUntil:   time.Now().Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	svc := NewService(repo)
	template, err := svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      1,
		ScopeID:        1,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         `{"target":"example.com"}`,
		Enabled:        true,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	require.NoError(t, err)
	run, err := svc.CreateTaskRun(context.Background(), CreateTaskRunInput{
		TemplateID: template.ID,
		ProjectID:  1,
		ActorID:    "alice",
	})
	require.NoError(t, err)

	err = svc.MarkTaskRunSucceeded(context.Background(), UpdateTaskRunStatusInput{
		RunID:       run.ID,
		ProjectID:   1,
		ActorID:     "alice",
		ResultCount: 8,
	})
	assert.ErrorIs(t, err, ErrInvalidRunTransition)

	err = svc.MarkTaskRunRunning(context.Background(), UpdateTaskRunStatusInput{
		RunID:     run.ID,
		ProjectID: 1,
		ActorID:   "alice",
	})
	require.NoError(t, err)

	err = svc.MarkTaskRunFailed(context.Background(), UpdateTaskRunStatusInput{
		RunID:        run.ID,
		ProjectID:    1,
		ActorID:      "alice",
		ResultCount:  3,
		ErrorSummary: "timeout",
	})
	require.NoError(t, err)

	err = svc.MarkTaskRunRunning(context.Background(), UpdateTaskRunStatusInput{
		RunID:     run.ID,
		ProjectID: 1,
		ActorID:   "alice",
	})
	assert.ErrorIs(t, err, ErrInvalidRunTransition)
}

func TestSetAndDeleteTaskTemplateAudit(t *testing.T) {
	repo := newFakeRepo()
	auditSink := &fakeAudit{}
	_, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    time.Now().Add(-time.Minute),
		ValidUntil:   time.Now().Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)

	svc := NewService(repo, WithAuditSink(auditSink))
	template, err := svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      1,
		ScopeID:        1,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         `{"target":"example.com"}`,
		Enabled:        true,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	require.NoError(t, err)

	_, err = svc.SetTaskTemplateEnabled(context.Background(), SetTaskTemplateEnabledInput{
		TemplateID: template.ID,
		ProjectID:  1,
		Enabled:    false,
		ActorID:    "alice",
	})
	require.NoError(t, err)
	require.NoError(t, svc.DeleteTaskTemplate(context.Background(), DeleteTaskTemplateInput{
		TemplateID: template.ID,
		ProjectID:  1,
		ActorID:    "alice",
	}))

	assert.Equal(t, ActionTemplateCreate, auditSink.events[0].Action)
	assert.Equal(t, ActionTemplateEnable, auditSink.events[1].Action)
	assert.Equal(t, ActionTemplateDelete, auditSink.events[2].Action)
}

func TestBuildDispatchPlanSuccess(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, `{
		"targets":[
			{"type":"domain","value":" Example.COM. "},
			{"type":"url","value":"https://example.com:443/path"}
		],
		"options":{"profile":"standard"}
	}`)

	plan, err := svc.BuildDispatchPlan(context.Background(), 1, run.ID, "alice")
	require.NoError(t, err)
	assert.Equal(t, run.ID, plan.RunID)
	assert.Equal(t, TaskTypeDNS, plan.TaskType)
	assert.Equal(t, []DispatchTarget{
		{Type: TargetTypeDomain, Value: "example.com"},
		{Type: TargetTypeURL, Value: "https://example.com:443"},
	}, plan.Targets)
	assert.Equal(t, "standard", plan.Options["profile"])
	assert.Equal(t, 20, plan.RateLimit)
	assert.Equal(t, 10, plan.Concurrency)
}

func TestBuildDispatchPlanRejectsInvalidConfig(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, `{"options":{}}`)

	_, err := svc.BuildDispatchPlan(context.Background(), 1, run.ID, "alice")
	assert.ErrorIs(t, err, ErrInvalidTaskConfig)
}

func TestBuildDispatchPlanRejectsDangerousTarget(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, `{
		"targets":[{"type":"url","value":"http://localhost"}]
	}`)

	_, err := svc.BuildDispatchPlan(context.Background(), 1, run.ID, "alice")
	assert.ErrorIs(t, err, ErrDangerousTarget)
}

func TestBuildDispatchPlanRejectsInactiveScope(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusInactive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))

	_, err := svc.BuildDispatchPlan(context.Background(), 1, run.ID, "alice")
	var denied DispatchDeniedError
	require.ErrorAs(t, err, &denied)
	assert.ErrorIs(t, err, ErrDispatchTargetDenied)
	assert.Equal(t, ReasonScopeInactive, denied.Reason)
}

func TestBuildDispatchPlanRejectsExpiredScope(t *testing.T) {
	repo := newFakeRepo()
	now := time.Now().UTC()
	scopeID, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       StatusActive,
		AuthorizedBy: "alice",
		ValidFrom:    now.Add(-2 * time.Hour),
		ValidUntil:   now.Add(-time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
		TenantID:   "t1",
		OrgID:      "o1",
		ProjectID:  1,
		ScopeID:    scopeID,
		TargetType: TargetTypeDomain,
		MatchMode:  MatchModeInclude,
		Value:      "example.com",
		ActorID:    "alice",
	}))
	svc := NewService(repo, WithNow(func() time.Time { return now }))
	template, run := createTemplateAndRun(t, svc, scopeID, true, dispatchConfigFor("example.com"))

	_, err = svc.BuildDispatchPlan(context.Background(), 1, run.ID, "alice")
	var denied DispatchDeniedError
	require.ErrorAs(t, err, &denied)
	assert.Equal(t, template.ID, run.TemplateID)
	assert.Equal(t, ReasonScopeExpired, denied.Reason)
}

func TestBuildDispatchPlanRejectsExcludedTarget(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("blocked.example.com"))

	_, err := svc.BuildDispatchPlan(context.Background(), 1, run.ID, "alice")
	var denied DispatchDeniedError
	require.ErrorAs(t, err, &denied)
	assert.Equal(t, ReasonExcluded, denied.Reason)
}

func TestBuildDispatchPlanRejectsNoMatch(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("other.example.com"))

	_, err := svc.BuildDispatchPlan(context.Background(), 1, run.ID, "alice")
	var denied DispatchDeniedError
	require.ErrorAs(t, err, &denied)
	assert.Equal(t, ReasonNoMatch, denied.Reason)
}

func TestBuildDispatchPlanRejectsNonPendingRun(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	require.NoError(t, svc.MarkTaskRunRunning(context.Background(), UpdateTaskRunStatusInput{
		RunID:     run.ID,
		ProjectID: 1,
		ActorID:   "alice",
	}))

	_, err := svc.BuildDispatchPlan(context.Background(), 1, run.ID, "alice")
	assert.ErrorIs(t, err, ErrTaskRunNotDispatchable)
}

func TestBuildDispatchPlanRejectsDisabledTemplate(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, false, TaskRunStatusPending, dispatchConfigFor("example.com"))

	_, err := svc.BuildDispatchPlan(context.Background(), 1, run.ID, "alice")
	assert.ErrorIs(t, err, ErrTemplateDisabled)
}

func TestBuildDispatchPlanProjectScoped(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))

	_, err := svc.BuildDispatchPlan(context.Background(), 2, run.ID, "alice")
	assert.ErrorIs(t, err, ErrNotFound)
}

func newDispatchPlanFixture(t *testing.T, scopeStatus string, templateEnabled bool, runStatus string, config string) (*Service, *TaskTemplate, *TaskRun) {
	t.Helper()
	repo := newFakeRepo()
	now := time.Now().UTC()
	scopeID, err := repo.CreateScope(context.Background(), CreateScopeParams{
		TenantID:     "t1",
		OrgID:        "o1",
		ProjectID:    1,
		Name:         "scope",
		Status:       scopeStatus,
		AuthorizedBy: "alice",
		ValidFrom:    now.Add(-time.Minute),
		ValidUntil:   now.Add(time.Hour),
		ActorID:      "alice",
	})
	require.NoError(t, err)
	for _, target := range []ScopeTargetInput{
		{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com"},
		{TargetType: TargetTypeURL, MatchMode: MatchModeInclude, Value: "https://example.com:443"},
		{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "blocked.example.com"},
		{TargetType: TargetTypeDomain, MatchMode: MatchModeExclude, Value: "blocked.example.com"},
	} {
		normalized, nerr := normalizeScopeTarget(target, "alice")
		require.NoError(t, nerr)
		require.NoError(t, repo.InsertScopeTarget(context.Background(), InsertScopeTargetParams{
			TenantID:   "t1",
			OrgID:      "o1",
			ProjectID:  1,
			ScopeID:    scopeID,
			TargetType: normalized.TargetType,
			MatchMode:  normalized.MatchMode,
			Value:      normalized.Value,
			ActorID:    "alice",
		}))
	}

	svc := NewService(repo, WithNow(func() time.Time { return now }))
	template, run := createTemplateAndRun(t, svc, scopeID, templateEnabled, config)
	if runStatus != TaskRunStatusPending {
		stored := repo.runs[1][run.ID]
		stored.Status = runStatus
		run.Status = runStatus
	}
	return svc, template, run
}

func createTemplateAndRun(t *testing.T, svc *Service, scopeID uint64, templateEnabled bool, config string) (*TaskTemplate, *TaskRun) {
	t.Helper()
	template, err := svc.CreateTaskTemplate(context.Background(), CreateTaskTemplateInput{
		TenantID:       "t1",
		OrgID:          "o1",
		ProjectID:      1,
		ScopeID:        scopeID,
		Name:           "template",
		TaskType:       TaskTypeDNS,
		Config:         config,
		Enabled:        templateEnabled,
		TimeoutSeconds: 30,
		RateLimit:      20,
		Concurrency:    10,
		RetryLimit:     3,
		ActorID:        "alice",
	})
	require.NoError(t, err)
	runID, err := svc.repo.CreateTaskRun(context.Background(), CreateTaskRunParams{
		TenantID:       template.TenantID,
		OrgID:          template.OrgID,
		ProjectID:      template.ProjectID,
		TemplateID:     template.ID,
		ScopeID:        template.ScopeID,
		TaskType:       template.TaskType,
		Status:         TaskRunStatusPending,
		Progress:       0,
		TimeoutSeconds: template.TimeoutSeconds,
		RateLimit:      template.RateLimit,
		Concurrency:    template.Concurrency,
		RetryLimit:     template.RetryLimit,
		ActorID:        "alice",
	})
	require.NoError(t, err)
	run, err := svc.repo.GetTaskRun(context.Background(), template.ProjectID, runID)
	require.NoError(t, err)
	return template, run
}

func dispatchConfigFor(target string) string {
	return `{"targets":[{"type":"domain","value":"` + target + `"}]}`
}

func TestDispatchTaskRunSuccessRecordsEngineJobAndRunning(t *testing.T) {
	engine := &fakeEngine{ids: []string{"job-123"}}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.engine = engine

	out, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID:   1,
		RunID:       run.ID,
		ActorID:     "alice",
		CallbackURL: "https://asm.example.com/callback",
	})
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusRunning, out.Status)
	assert.Equal(t, "job-123", out.EngineJobID)
	assert.Equal(t, 1, out.Attempt)
	require.Len(t, engine.jobs, 1)
	assert.Equal(t, uint64(1), engine.jobs[0].RunID)
	assert.Equal(t, TaskTypeDNS, engine.jobs[0].JobType)
	assert.Equal(t, "https://asm.example.com/callback", engine.jobs[0].CallbackURL)
	assert.Equal(t, 30*time.Second, engine.jobs[0].Timeout)
}

func TestDispatchTaskRunRetriesThenSucceeds(t *testing.T) {
	engine := &fakeEngine{
		errs: []error{ErrEngineDispatch, nil},
		ids:  []string{"job-456"},
	}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.engine = engine

	out, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1,
		RunID:     run.ID,
		ActorID:   "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusRunning, out.Status)
	assert.Equal(t, "job-456", out.EngineJobID)
	assert.Equal(t, 2, out.Attempt)
	assert.Equal(t, 2, engine.dispatchCalls)
}

func TestDispatchTaskRunFailureMarksRunFailedAfterRetryLimit(t *testing.T) {
	dispatchErr := errors.New("engine unavailable")
	engine := &fakeEngine{errs: []error{dispatchErr, dispatchErr, dispatchErr, dispatchErr}}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.engine = engine

	out, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1,
		RunID:     run.ID,
		ActorID:   "alice",
	})
	assert.ErrorIs(t, err, dispatchErr)
	require.NotNil(t, out)
	assert.Equal(t, TaskRunStatusFailed, out.Status)
	assert.Contains(t, out.ErrorSummary, "engine unavailable")
	assert.Equal(t, 4, out.Attempt)
	assert.Equal(t, 4, engine.dispatchCalls)
}

func TestDispatchTaskRunRequiresEngineAdapter(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))

	_, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1,
		RunID:     run.ID,
		ActorID:   "alice",
	})
	assert.ErrorIs(t, err, ErrEngineNotConfigured)
}

func TestCancelDispatchedTaskRunCallsEngineAndMarksCancelled(t *testing.T) {
	engine := &fakeEngine{ids: []string{"job-cancel"}}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.engine = engine
	dispatched, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1,
		RunID:     run.ID,
		ActorID:   "alice",
	})
	require.NoError(t, err)

	err = svc.CancelDispatchedTaskRun(context.Background(), UpdateTaskRunStatusInput{
		RunID:        dispatched.ID,
		ProjectID:    1,
		ActorID:      "alice",
		ErrorSummary: "operator cancelled",
	})
	require.NoError(t, err)
	cancelled, err := svc.GetTaskRun(context.Background(), 1, dispatched.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, engine.cancelCalls)
	assert.Equal(t, TaskRunStatusCancelled, cancelled.Status)
	assert.Equal(t, "operator cancelled", cancelled.ErrorSummary)
}

func TestCancelDispatchedTaskRunCancelsPendingRunWithoutEngine(t *testing.T) {
	engine := &fakeEngine{}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.engine = engine

	err := svc.CancelDispatchedTaskRun(context.Background(), UpdateTaskRunStatusInput{
		RunID:     run.ID,
		ProjectID: 1,
		ActorID:   "alice",
	})
	require.NoError(t, err)
	cancelled, getErr := svc.GetTaskRun(context.Background(), 1, run.ID)
	require.NoError(t, getErr)
	assert.Equal(t, TaskRunStatusCancelled, cancelled.Status)
	assert.Equal(t, 0, engine.cancelCalls)
	require.NoError(t, svc.CancelDispatchedTaskRun(context.Background(), UpdateTaskRunStatusInput{
		RunID: run.ID, ProjectID: 1, ActorID: "alice",
	}))
}

func TestReconcileTaskRunMarksEngineSuccess(t *testing.T) {
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	engine := &fakeEngine{ids: []string{"job-reconcile"}, statuses: []EngineJobStatus{{Status: EngineJobStatusSuccess, ResultCount: 9}}}
	svc.engine = engine
	dispatched, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1,
		RunID:     run.ID,
		ActorID:   "alice",
	})
	require.NoError(t, err)

	updated, err := svc.ReconcileTaskRun(context.Background(), ReconcileTaskRunInput{
		ProjectID: 1,
		RunID:     dispatched.ID,
		ActorID:   "system",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, engine.statusCalls)
	assert.Equal(t, TaskRunStatusSuccess, updated.Status)
	assert.Equal(t, uint64(9), updated.ResultCount)
}

func TestReconcileTaskRunTerminalAndRunningMappings(t *testing.T) {
	tests := []struct {
		name         string
		engineStatus string
		wantStatus   string
	}{
		{name: "partial", engineStatus: EngineJobStatusPartialSuccess, wantStatus: TaskRunStatusPartial},
		{name: "failed", engineStatus: EngineJobStatusFailed, wantStatus: TaskRunStatusFailed},
		{name: "cancelled", engineStatus: EngineJobStatusCancelled, wantStatus: TaskRunStatusCancelled},
		{name: "running", engineStatus: EngineJobStatusRunning, wantStatus: TaskRunStatusRunning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
			engine := &fakeEngine{ids: []string{"job-" + tt.name}, statuses: []EngineJobStatus{{
				Status: tt.engineStatus, ResultCount: 4, ErrorSummary: tt.name,
			}}}
			svc.engine = engine
			dispatched, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "alice"})
			require.NoError(t, err)
			updated, err := svc.ReconcileTaskRun(context.Background(), ReconcileTaskRunInput{ProjectID: 1, RunID: dispatched.ID, ActorID: "system"})
			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, updated.Status)
		})
	}
}

func TestReconcileTimedOutRunsCancelsStillRunningEngineJob(t *testing.T) {
	now := time.Now().UTC()
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	engine := &fakeEngine{ids: []string{"job-timeout"}, statuses: []EngineJobStatus{{Status: EngineJobStatusRunning}}}
	svc.engine = engine
	svc.nowFn = func() time.Time { return now }
	dispatched, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1,
		RunID:     run.ID,
		ActorID:   "alice",
	})
	require.NoError(t, err)
	stored := svc.repo.(*fakeRepo).runs[1][dispatched.ID]
	stored.DispatchedAt = now.Add(-time.Duration(stored.TimeoutSeconds+1) * time.Second)
	svc.nowFn = func() time.Time { return now }

	result, err := svc.ReconcileTimedOutRuns(context.Background(), ReconcileTimedOutRunsInput{
		ActorID: "system",
		Limit:   10,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, 1, result.Updated)
	assert.Equal(t, 1, result.Cancelled)
	assert.Equal(t, 1, engine.statusCalls)
	assert.Equal(t, 1, engine.cancelCalls)
	updated, err := svc.GetTaskRun(context.Background(), 1, dispatched.ID)
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusFailed, updated.Status)
	assert.Equal(t, "task run timed out", updated.ErrorSummary)
}

func TestReconcileTimeoutClosesLocallyWhenEngineCancelFails(t *testing.T) {
	now := time.Now().UTC()
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	engine := &fakeEngine{
		ids: []string{"job-timeout-cancel-failure"}, statuses: []EngineJobStatus{{Status: EngineJobStatusRunning}},
		cancelErr: errors.New("engine unreachable"),
	}
	svc.engine = engine
	svc.nowFn = func() time.Time { return now }
	dispatched, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "alice"})
	require.NoError(t, err)
	stored := svc.repo.(*fakeRepo).runs[1][dispatched.ID]
	stored.DispatchedAt = now.Add(-time.Duration(stored.TimeoutSeconds+1) * time.Second)

	result, err := svc.ReconcileTimedOutRuns(context.Background(), ReconcileTimedOutRunsInput{ActorID: "system", Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Updated)
	updated, err := svc.GetTaskRun(context.Background(), 1, dispatched.ID)
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusFailed, updated.Status)
	assert.Equal(t, "task run timed out; engine cancellation failed", updated.ErrorSummary)
}

func TestHandleCallbackAcceptsNewRunningRunCallback(t *testing.T) {
	now := time.Now().UTC()
	enqueuer := &fakeCallbackEnqueuer{}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = enqueuer
	engine := &fakeEngine{ids: []string{"job-callback"}}
	svc.engine = engine
	dispatched, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1,
		RunID:     run.ID,
		ActorID:   "alice",
	})
	require.NoError(t, err)

	raw := validCallbackRaw(t, dispatched.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 3)
	input := signedCallbackInput(1, dispatched.ID, 1, now, "callback-secret", raw)
	result, err := svc.HandleCallback(context.Background(), input)
	require.NoError(t, err)
	assert.False(t, result.Duplicate)
	assert.Equal(t, 1, enqueuer.calls)
	assert.Equal(t, uint64(3), enqueuer.items[0].ResultCount)
	updated, err := svc.GetTaskRun(context.Background(), 1, dispatched.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), updated.ResultCount)
	assert.Equal(t, now, updated.LastCallbackAt)
}

func TestHandleCallbackDuplicateSeqDoesNotEnqueueAgain(t *testing.T) {
	now := time.Now().UTC()
	enqueuer := &fakeCallbackEnqueuer{}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = enqueuer
	svc.engine = &fakeEngine{ids: []string{"job-callback"}}
	dispatched, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1,
		RunID:     run.ID,
		ActorID:   "alice",
	})
	require.NoError(t, err)
	raw := validCallbackRaw(t, dispatched.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 3)
	input := signedCallbackInput(1, dispatched.ID, 1, now, "callback-secret", raw)
	_, err = svc.HandleCallback(context.Background(), input)
	require.NoError(t, err)

	result, err := svc.HandleCallback(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, result.Duplicate)
	assert.Equal(t, 2, enqueuer.calls)
}

func TestHandleCallbackRejectsInvalidSignatureAndReplay(t *testing.T) {
	now := time.Now().UTC()
	audits := &fakeAudit{}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.auditSink = audits
	raw := validCallbackRaw(t, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	input := signedCallbackInput(1, run.ID, 1, now, "callback-secret", raw)
	input.Signature = "bad"
	_, err := svc.HandleCallback(context.Background(), input)
	assert.ErrorIs(t, err, ErrInvalidCallbackSignature)
	require.Len(t, audits.events, 1)
	assert.Equal(t, ActionCallbackReject, audits.events[0].Action)
	assert.Equal(t, "INVALID_CALLBACK_SIGNATURE", audits.events[0].ErrorCode)

	old := signedCallbackInput(1, run.ID, 1, now.Add(-10*time.Minute), "callback-secret", raw)
	_, err = svc.HandleCallback(context.Background(), old)
	assert.ErrorIs(t, err, ErrCallbackReplay)
	require.Len(t, audits.events, 2)
	assert.Equal(t, "CALLBACK_REPLAY", audits.events[1].ErrorCode)
}

func TestHandleCallbackRejectsNonRunningRun(t *testing.T) {
	now := time.Now().UTC()
	audits := &fakeAudit{}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.auditSink = audits
	raw := validCallbackRaw(t, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	input := signedCallbackInput(1, run.ID, 1, now, "callback-secret", raw)

	_, err := svc.HandleCallback(context.Background(), input)
	assert.ErrorIs(t, err, ErrCallbackRunNotRunning)
	require.Len(t, audits.events, 1)
	assert.Equal(t, ActionCallbackReject, audits.events[0].Action)
	assert.Equal(t, "CALLBACK_RUN_NOT_RUNNING", audits.events[0].ErrorCode)
}

func signedCallbackInput(projectID, runID, seq uint64, ts time.Time, secret string, raw []byte) HandleCallbackInput {
	timestamp := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write(raw)
	return HandleCallbackInput{
		ProjectID: projectID,
		RunID:     runID,
		Seq:       seq,
		Timestamp: timestamp,
		Signature: hex.EncodeToString(mac.Sum(nil)),
		RawBody:   raw,
		Secret:    secret,
	}
}

func validCallbackRaw(t *testing.T, runID, seq uint64, phase, status string, resultCount int) []byte {
	t.Helper()
	observedAt := time.Date(2026, time.July, 13, 1, 2, 3, 0, time.UTC)
	assets := make([]map[string]any, 0, resultCount)
	for i := 0; i < resultCount; i++ {
		assets = append(assets, map[string]any{
			"client_ref":    "asset-" + strconv.Itoa(i+1),
			"asset_type":    "domain",
			"value":         "example.com",
			"source":        "baiyan",
			"provider":      "crtsh",
			"observed_at":   observedAt,
			"confidence":    90,
			"active_probe":  false,
			"evidence_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		})
	}
	raw, err := json.Marshal(map[string]any{
		"schema_version":  callbackSchemaVersion,
		"run_id":          runID,
		"seq":             seq,
		"phase":           phase,
		"status":          status,
		"result_count":    resultCount,
		"observed_at":     observedAt,
		"assets":          assets,
		"relations":       []any{},
		"exposures":       []any{},
		"provider_errors": []any{},
		"error_summary":   "",
	})
	require.NoError(t, err)
	return raw
}
