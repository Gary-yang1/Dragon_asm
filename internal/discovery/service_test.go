package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

type fakeRepo struct {
	scopes         map[uint64]map[uint64]*Scope
	targets        map[uint64]map[uint64][]*ScopeTarget
	clearCount     int
	nextScopeID    uint64
	nextTargetID   uint64
	templates      map[uint64]map[uint64]*TaskTemplate
	runs           map[uint64]map[uint64]*TaskRun
	nextTemplateID uint64
	nextRunID      uint64
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		scopes:    make(map[uint64]map[uint64]*Scope),
		targets:   make(map[uint64]map[uint64][]*ScopeTarget),
		templates: make(map[uint64]map[uint64]*TaskTemplate),
		runs:      make(map[uint64]map[uint64]*TaskRun),
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

func (r *fakeRepo) MarkRunRunning(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, startedAt time.Time) error {
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

func (r *fakeRepo) MarkRunSucceeded(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, resultCount uint64, now time.Time) error {
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
	_ = now
	_ = actorID
	run, ok := r.runs[projectID][runID]
	if !ok {
		return ErrNotFound
	}
	run.Attempt++
	return nil
}

type fakeAudit struct {
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	f.events = append(f.events, e)
	return nil
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
	_, err := repo.CreateScope(context.Background(), CreateScopeParams{
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
	_, err = repo.CreateScope(context.Background(), CreateScopeParams{
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

	svc := NewService(repo)
	scopes, err := svc.ListScopes(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, scopes, 1)
	assert.Equal(t, uint64(1), scopes[0].ID)
	assert.Equal(t, uint64(1), scopes[0].ProjectID)
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
	assert.Equal(t, template.ScopeID, run.ScopeID)
	assert.Equal(t, template.TaskType, run.TaskType)
	assert.Equal(t, TaskRunStatusPending, run.Status)
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
