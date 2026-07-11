//revive:disable:exported

package discovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var (
	ErrInvalidScopeAction    = errors.New("discovery: invalid scope action")
	ErrInvalidTemplateAction = errors.New("discovery: invalid template action")
	ErrInvalidRunTransition  = errors.New("discovery: invalid task run transition")
)

// DispatchDeniedError preserves the exact target and scope policy reason for tests
// and future API error mapping without exposing full task config.
type DispatchDeniedError struct {
	Target string
	Reason ScopeRejectReason
}

func (e DispatchDeniedError) Error() string {
	return fmt.Sprintf("%s: target=%s reason=%s", ErrDispatchTargetDenied.Error(), e.Target, e.Reason)
}

func (e DispatchDeniedError) Unwrap() error {
	return ErrDispatchTargetDenied
}

var validRunTransitions = map[string]map[string]bool{
	TaskRunStatusPending: {
		TaskRunStatusRunning:   true,
		TaskRunStatusCancelled: true,
	},
	TaskRunStatusRunning: {
		TaskRunStatusSuccess:   true,
		TaskRunStatusPartial:   true,
		TaskRunStatusFailed:    true,
		TaskRunStatusCancelled: true,
	},
}

// Service applies the M2-1/M2-2 discovery scope/task operations and writes audit events.
type Service struct {
	repo             Repository
	db               *sql.DB
	engine           EngineAdapter
	callbackEnqueuer CallbackEnqueuer
	auditSink        auditRecorder
	nowFn            func() time.Time
}

// auditRecorder is the minimal audit sink used by this service.
type auditRecorder interface {
	Record(ctx context.Context, e audit.Event) error
}

// ServiceOption configures Service behavior.
type ServiceOption func(*Service)

// WithDB enables transaction boundaries for mutating APIs.
func WithDB(db *sql.DB) ServiceOption {
	return func(s *Service) {
		s.db = db
	}
}

// WithAuditSink injects an audit recorder.
func WithAuditSink(sink auditRecorder) ServiceOption {
	return func(s *Service) {
		s.auditSink = sink
	}
}

// WithEngineAdapter injects the external engine adapter used by M2-4 dispatch.
func WithEngineAdapter(engine EngineAdapter) ServiceOption {
	return func(s *Service) {
		s.engine = engine
	}
}

// WithCallbackEnqueuer injects the worker queue producer used by callback ingest.
func WithCallbackEnqueuer(enqueuer CallbackEnqueuer) ServiceOption {
	return func(s *Service) {
		s.callbackEnqueuer = enqueuer
	}
}

// WithNow overrides time source for deterministic tests.
func WithNow(now func() time.Time) ServiceOption {
	return func(s *Service) {
		s.nowFn = now
	}
}

// NewService builds the discovery service.
func NewService(repo Repository, opts ...ServiceOption) *Service {
	s := &Service{
		repo:  repo,
		nowFn: func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Service) runInTx(ctx context.Context, fn func(ctx context.Context, repo Repository, auditSink auditRecorder) error) error {
	if s.db == nil {
		return fn(ctx, s.repo, s.auditSink)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txRepo := NewRepository(dbgen.New(tx))
	txAudit := audit.NewService(audit.NewRepository(dbgen.New(tx)))
	if err := fn(ctx, txRepo, txAudit); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// CreateScope creates a scope and optional include/exclude targets.
func (s *Service) CreateScope(ctx context.Context, in CreateScopeInput) (*Scope, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	status, err := validateStatus(in.Status)
	if err != nil {
		return nil, err
	}
	if err := validateScopeMeta(in.TenantID, in.OrgID, in.Name, in.AuthorizedBy, in.ActorID); err != nil {
		return nil, err
	}
	if err := validateScopeWindow(in.ValidFrom, in.ValidUntil); err != nil {
		return nil, err
	}
	targets, err := validateScopeTargets(in.Targets, in.ActorID)
	if err != nil {
		return nil, err
	}

	var scopeID uint64
	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		var err error
		scopeID, err = repo.CreateScope(ctx, CreateScopeParams{
			TenantID:     in.TenantID,
			OrgID:        in.OrgID,
			ProjectID:    in.ProjectID,
			Name:         in.Name,
			Status:       status,
			AuthorizedBy: in.AuthorizedBy,
			ValidFrom:    in.ValidFrom,
			ValidUntil:   in.ValidUntil,
			ActorID:      in.ActorID,
		})
		if err != nil {
			return err
		}

		for _, t := range targets {
			if err := repo.InsertScopeTarget(ctx, InsertScopeTargetParams{
				TenantID:   in.TenantID,
				OrgID:      in.OrgID,
				ProjectID:  in.ProjectID,
				ScopeID:    scopeID,
				TargetType: t.TargetType,
				MatchMode:  t.MatchMode,
				Value:      t.Value,
				ActorID:    in.ActorID,
			}); err != nil {
				return err
			}
		}

		scope, err := repo.GetScope(ctx, in.ProjectID, scopeID)
		if err != nil {
			return err
		}
		return s.recordAuditWithSink(ctx, txAudit, ActionScopeCreate, scope, nil, in.ActorID, in.Meta)
	}); err != nil {
		return nil, err
	}

	return s.GetScope(ctx, in.ProjectID, scopeID)
}

// UpdateScope patches fields and optionally replaces target list.
func (s *Service) UpdateScope(ctx context.Context, in UpdateScopeInput) (*Scope, error) {
	if in.ProjectID == 0 || in.ScopeID == 0 {
		return nil, ErrInvalidScopeID
	}

	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetScope(ctx, in.ProjectID, in.ScopeID)
		if err != nil {
			return err
		}

		name := before.Name
		if in.Name != nil {
			name = strings.TrimSpace(*in.Name)
			if len(name) == 0 || len(name) > maxScopeNameLen {
				return ErrInvalidName
			}
		}
		authorizedBy := before.AuthorizedBy
		if in.AuthorizedBy != nil {
			authorizedBy = strings.TrimSpace(*in.AuthorizedBy)
			if len(authorizedBy) == 0 || len(authorizedBy) > maxAuthorizedLen {
				return ErrInvalidAuthorizedBy
			}
		}
		status := before.Status
		if in.Status != nil {
			st, err := validateStatus(strings.TrimSpace(*in.Status))
			if err != nil {
				return err
			}
			status = st
		}
		validFrom := before.ValidFrom
		if in.ValidFrom != nil {
			validFrom = *in.ValidFrom
		}
		validUntil := before.ValidUntil
		if in.ValidUntil != nil {
			validUntil = *in.ValidUntil
		}
		if err := validateScopeWindow(validFrom, validUntil); err != nil {
			return err
		}
		if err := validateScopeMeta(in.TenantID, in.OrgID, name, authorizedBy, in.ActorID); err != nil {
			return err
		}

		targets := []ScopeTarget(nil)
		if in.Targets != nil {
			targets, err = validateScopeTargets(*in.Targets, in.ActorID)
			if err != nil {
				return err
			}

			if err := repo.ClearScopeTargets(ctx, in.ProjectID, in.ScopeID, in.ActorID, s.nowFn()); err != nil {
				return err
			}
		}

		if err := repo.UpdateScope(ctx, UpdateScopeParams{
			ScopeID:      in.ScopeID,
			TenantID:     in.TenantID,
			OrgID:        in.OrgID,
			ProjectID:    in.ProjectID,
			Name:         name,
			Status:       status,
			AuthorizedBy: authorizedBy,
			ValidFrom:    validFrom,
			ValidUntil:   validUntil,
			ActorID:      in.ActorID,
		}); err != nil {
			return err
		}

		if in.Targets != nil {
			for _, t := range targets {
				if err := repo.InsertScopeTarget(ctx, InsertScopeTargetParams{
					TenantID:   in.TenantID,
					OrgID:      in.OrgID,
					ProjectID:  in.ProjectID,
					ScopeID:    in.ScopeID,
					TargetType: t.TargetType,
					MatchMode:  t.MatchMode,
					Value:      t.Value,
					ActorID:    in.ActorID,
				}); err != nil {
					return err
				}
			}
		}

		after, err := repo.GetScope(ctx, in.ProjectID, in.ScopeID)
		if err != nil {
			return err
		}
		if err := s.recordAuditWithSink(ctx, txAudit, ActionScopeUpdate, before, after, in.ActorID, in.Meta); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return s.GetScope(ctx, in.ProjectID, in.ScopeID)
}

// DeactivateScope marks a live scope inactive.
func (s *Service) DeactivateScope(ctx context.Context, in DeactivateScopeInput) error {
	if in.ProjectID == 0 || in.ScopeID == 0 {
		return ErrInvalidScopeID
	}
	return s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetScope(ctx, in.ProjectID, in.ScopeID)
		if err != nil {
			return err
		}
		if err := repo.DeactivateScope(ctx, in.ProjectID, in.ScopeID, in.ActorID, s.nowFn); err != nil {
			return err
		}
		after, err := repo.GetScope(ctx, in.ProjectID, in.ScopeID)
		if err != nil {
			return err
		}
		return s.recordAuditWithSink(ctx, txAudit, ActionScopeDeactivate, before, after, in.ActorID, in.Meta)
	})
}

// GetScope returns one live scope with targets.
func (s *Service) GetScope(ctx context.Context, projectID, scopeID uint64) (*Scope, error) {
	if projectID == 0 || scopeID == 0 {
		return nil, ErrInvalidScopeID
	}
	scope, err := s.repo.GetScope(ctx, projectID, scopeID)
	if err != nil {
		return nil, err
	}
	targets, err := s.repo.ListScopeTargets(ctx, projectID, scopeID)
	if err != nil {
		return nil, err
	}
	scope.Targets = targets
	return scope, nil
}

// ListScopes returns live scopes for one project.
func (s *Service) ListScopes(ctx context.Context, projectID uint64) ([]*Scope, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.ListScopes(ctx, projectID)
}

// IsTargetAllowed validates time window + target policy and returns a reason.
func (s *Service) IsTargetAllowed(ctx context.Context, projectID, scopeID uint64, rawTarget string) (bool, ScopeRejectReason, error) {
	if projectID == 0 || scopeID == 0 {
		return false, ReasonScopeNotFound, ErrInvalidScopeID
	}
	parsed, err := parseTarget(rawTarget)
	if err != nil {
		if errors.Is(err, ErrDangerousTarget) {
			return false, ReasonDangerous, err
		}
		return false, ReasonTargetInvalid, err
	}

	scope, err := s.repo.GetScope(ctx, projectID, scopeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, ReasonScopeNotFound, err
		}
		return false, ReasonSystemError, err
	}

	now := s.nowFn()
	if scope.Status != StatusActive {
		return false, ReasonScopeInactive, nil
	}
	if now.Before(scope.ValidFrom) {
		return false, ReasonNotStarted, nil
	}
	if now.After(scope.ValidUntil) {
		return false, ReasonScopeExpired, nil
	}

	targets, err := s.repo.ListScopeTargets(ctx, projectID, scopeID)
	if err != nil {
		return false, ReasonSystemError, err
	}

	for _, t := range targets {
		if t.MatchMode != MatchModeExclude {
			continue
		}
		if matchTarget(t, parsed) {
			return false, ReasonExcluded, nil
		}
	}
	for _, t := range targets {
		if t.MatchMode != MatchModeInclude {
			continue
		}
		if matchTarget(t, parsed) {
			return true, ReasonAllowed, nil
		}
	}
	return false, ReasonNoMatch, nil
}

// CreateTaskTemplate creates a task template and validates scope ownership by project.
func (s *Service) CreateTaskTemplate(ctx context.Context, in CreateTaskTemplateInput) (*TaskTemplate, error) {
	if err := validateTemplateMeta(in.TenantID, in.OrgID, in.Name, in.ScopeID, in.ProjectID, in.TaskType, in.ActorID); err != nil {
		return nil, err
	}
	if err := validateTemplateSchedule(in.Schedule); err != nil {
		return nil, err
	}
	config, err := normalizeTemplateConfig(in.Config)
	if err != nil {
		return nil, err
	}
	if err := validateTaskLimits(in.TimeoutSeconds, in.RateLimit, in.Concurrency, in.RetryLimit); err != nil {
		return nil, err
	}
	template := (*TaskTemplate)(nil)

	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		if _, err := repo.GetScope(ctx, in.ProjectID, in.ScopeID); err != nil {
			return err
		}
		id, err := repo.CreateTaskTemplate(ctx, CreateTaskTemplateParams{
			TenantID:       in.TenantID,
			OrgID:          in.OrgID,
			ProjectID:      in.ProjectID,
			ScopeID:        in.ScopeID,
			Name:           in.Name,
			TaskType:       in.TaskType,
			Config:         config,
			Schedule:       in.Schedule,
			Enabled:        in.Enabled,
			TimeoutSeconds: in.TimeoutSeconds,
			RateLimit:      in.RateLimit,
			Concurrency:    in.Concurrency,
			RetryLimit:     in.RetryLimit,
			ActorID:        in.ActorID,
		})
		if err != nil {
			return err
		}
		t, err := repo.GetTaskTemplate(ctx, in.ProjectID, id)
		if err != nil {
			return err
		}
		if err := s.recordAuditWithSink(ctx, txAudit, ActionTemplateCreate, nil, t, in.ActorID, in.Meta); err != nil {
			return err
		}
		template = t
		return nil
	}); err != nil {
		return nil, err
	}
	return template, nil
}

// UpdateTaskTemplate updates fields but does not change scope association.
func (s *Service) UpdateTaskTemplate(ctx context.Context, in UpdateTaskTemplateInput) (*TaskTemplate, error) {
	if in.ProjectID == 0 || in.TemplateID == 0 {
		return nil, ErrInvalidTemplateID
	}
	if in.ActorID == "" || len(in.ActorID) > maxActorLen {
		return nil, ErrInvalidActorID
	}
	var updated *TaskTemplate

	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetTaskTemplate(ctx, in.ProjectID, in.TemplateID)
		if err != nil {
			return err
		}

		name := before.Name
		if in.Name != nil {
			name = strings.TrimSpace(*in.Name)
			if len(name) == 0 || len(name) > maxTemplateName {
				return ErrInvalidName
			}
		}
		taskType := before.TaskType
		if in.TaskType != nil {
			t, err := validateTaskType(*in.TaskType)
			if err != nil {
				return err
			}
			taskType = t
		}
		config := before.Config
		if in.Config != nil {
			var normalizedConfig string
			normalizedConfig, err = normalizeTemplateConfig(*in.Config)
			if err != nil {
				return err
			}
			config = normalizedConfig
		}
		schedule := before.Schedule
		if in.Schedule != nil {
			if err := validateTemplateSchedule(*in.Schedule); err != nil {
				return err
			}
			schedule = *in.Schedule
		}

		timeoutSeconds := before.TimeoutSeconds
		if in.TimeoutSeconds != nil {
			timeoutSeconds = *in.TimeoutSeconds
		}
		rateLimit := before.RateLimit
		if in.RateLimit != nil {
			rateLimit = *in.RateLimit
		}
		concurrency := before.Concurrency
		if in.Concurrency != nil {
			concurrency = *in.Concurrency
		}
		retryLimit := before.RetryLimit
		if in.RetryLimit != nil {
			retryLimit = *in.RetryLimit
		}
		if err := validateTaskLimits(timeoutSeconds, rateLimit, concurrency, retryLimit); err != nil {
			return err
		}

		if err := repo.UpdateTaskTemplate(ctx, UpdateTaskTemplateParams{
			TemplateID:     in.TemplateID,
			TenantID:       in.TenantID,
			OrgID:          in.OrgID,
			ProjectID:      in.ProjectID,
			Name:           name,
			TaskType:       taskType,
			Config:         config,
			Schedule:       schedule,
			TimeoutSeconds: timeoutSeconds,
			RateLimit:      rateLimit,
			Concurrency:    concurrency,
			RetryLimit:     retryLimit,
			ActorID:        in.ActorID,
		}); err != nil {
			return err
		}
		after, err := repo.GetTaskTemplate(ctx, in.ProjectID, in.TemplateID)
		if err != nil {
			return err
		}
		if err := s.recordAuditWithSink(ctx, txAudit, ActionTemplateUpdate, before, after, in.ActorID, in.Meta); err != nil {
			return err
		}
		updated = after
		return nil
	}); err != nil {
		return nil, err
	}
	return updated, nil
}

// SetTaskTemplateEnabled updates template enabled flag.
func (s *Service) SetTaskTemplateEnabled(ctx context.Context, in SetTaskTemplateEnabledInput) (*TaskTemplate, error) {
	if in.ProjectID == 0 || in.TemplateID == 0 {
		return nil, ErrInvalidTemplateID
	}
	if len(in.ActorID) == 0 || len(in.ActorID) > maxActorLen {
		return nil, ErrInvalidActorID
	}
	var updated *TaskTemplate
	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetTaskTemplate(ctx, in.ProjectID, in.TemplateID)
		if err != nil {
			return err
		}
		if err := repo.SetTaskTemplateEnabled(ctx, in.ProjectID, in.TemplateID, in.Enabled, in.ActorID); err != nil {
			return err
		}
		after, err := repo.GetTaskTemplate(ctx, in.ProjectID, in.TemplateID)
		if err != nil {
			return err
		}
		if err := s.recordAuditWithSink(ctx, txAudit, ActionTemplateEnable, before, after, in.ActorID, in.Meta); err != nil {
			return err
		}
		updated = after
		return nil
	}); err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, ErrNotFound
	}
	return updated, nil
}

// DeleteTaskTemplate soft-deletes one task template.
func (s *Service) DeleteTaskTemplate(ctx context.Context, in DeleteTaskTemplateInput) error {
	if in.ProjectID == 0 || in.TemplateID == 0 {
		return ErrInvalidTemplateID
	}
	if len(in.ActorID) == 0 || len(in.ActorID) > maxActorLen {
		return ErrInvalidActorID
	}
	return s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetTaskTemplate(ctx, in.ProjectID, in.TemplateID)
		if err != nil {
			return err
		}
		if err := repo.DeleteTaskTemplate(ctx, in.ProjectID, in.TemplateID, in.ActorID); err != nil {
			return err
		}
		if err := s.recordAuditWithSink(ctx, txAudit, ActionTemplateDelete, before, nil, in.ActorID, in.Meta); err != nil {
			return err
		}
		return nil
	})
}

// GetTaskTemplate returns one live template.
func (s *Service) GetTaskTemplate(ctx context.Context, projectID, templateID uint64) (*TaskTemplate, error) {
	if projectID == 0 || templateID == 0 {
		return nil, ErrInvalidTemplateID
	}
	return s.repo.GetTaskTemplate(ctx, projectID, templateID)
}

// ListTaskTemplates returns one project's templates.
func (s *Service) ListTaskTemplates(ctx context.Context, projectID uint64) ([]*TaskTemplate, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.ListTaskTemplates(ctx, projectID)
}

// CreateTaskRun creates a pending run bound to a template.
func (s *Service) CreateTaskRun(ctx context.Context, in CreateTaskRunInput) (*TaskRun, error) {
	if in.ProjectID == 0 || in.TemplateID == 0 {
		return nil, ErrInvalidTemplateID
	}
	if in.ActorID == "" || len(in.ActorID) > maxActorLen {
		return nil, ErrInvalidActorID
	}
	var run *TaskRun

	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		template, err := repo.GetTaskTemplate(ctx, in.ProjectID, in.TemplateID)
		if err != nil {
			return err
		}
		if !template.Enabled {
			return ErrTemplateDisabled
		}
		id, err := repo.CreateTaskRun(ctx, CreateTaskRunParams{
			TenantID:       template.TenantID,
			OrgID:          template.OrgID,
			ProjectID:      in.ProjectID,
			TemplateID:     in.TemplateID,
			ScopeID:        template.ScopeID,
			TaskType:       template.TaskType,
			Status:         TaskRunStatusPending,
			Progress:       0,
			TimeoutSeconds: template.TimeoutSeconds,
			RateLimit:      template.RateLimit,
			Concurrency:    template.Concurrency,
			RetryLimit:     template.RetryLimit,
			Attempt:        0,
			EngineJobID:    "",
			DispatchedAt:   time.Time{},
			LastCallbackAt: time.Time{},
			ResultCount:    0,
			ActorID:        in.ActorID,
		})
		if err != nil {
			return err
		}
		run, err = repo.GetTaskRun(ctx, in.ProjectID, id)
		if err != nil {
			return err
		}
		if err := s.recordAuditWithSink(ctx, txAudit, ActionRunCreate, nil, run, in.ActorID, in.Meta); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return run, nil
}

// GetTaskRun returns one live run.
func (s *Service) GetTaskRun(ctx context.Context, projectID, runID uint64) (*TaskRun, error) {
	if projectID == 0 || runID == 0 {
		return nil, ErrInvalidTaskRunID
	}
	return s.repo.GetTaskRun(ctx, projectID, runID)
}

// ListTaskRuns returns one project's live task runs.
func (s *Service) ListTaskRuns(ctx context.Context, projectID uint64) ([]*TaskRun, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.ListTaskRuns(ctx, projectID)
}

// BuildDispatchPlan validates a pending run's targets against its project scope.
// It does not call the engine or mutate run status; M2-4 owns actual dispatch.
func (s *Service) BuildDispatchPlan(ctx context.Context, projectID, runID uint64, actorID string) (*DispatchPlan, error) {
	if projectID == 0 || runID == 0 {
		return nil, ErrInvalidTaskRunID
	}
	if actorID == "" || len(actorID) > maxActorLen {
		return nil, ErrInvalidActorID
	}

	run, err := s.repo.GetTaskRun(ctx, projectID, runID)
	if err != nil {
		return nil, err
	}
	if run.Status != TaskRunStatusPending {
		return nil, ErrTaskRunNotDispatchable
	}

	template, err := s.repo.GetTaskTemplate(ctx, projectID, run.TemplateID)
	if err != nil {
		return nil, err
	}
	if template.ProjectID != run.ProjectID || template.ID != run.TemplateID || template.ScopeID != run.ScopeID {
		return nil, ErrInvalidTemplate
	}
	if !template.Enabled {
		return nil, ErrTemplateDisabled
	}

	config, err := parseDispatchConfig(template.Config)
	if err != nil {
		return nil, err
	}
	for _, target := range config.Targets {
		allowed, reason, err := s.IsTargetAllowed(ctx, projectID, run.ScopeID, target.Value)
		if err != nil && reason == ReasonSystemError {
			return nil, err
		}
		if !allowed {
			return nil, DispatchDeniedError{Target: target.Value, Reason: reason}
		}
		if err != nil {
			return nil, err
		}
	}

	return &DispatchPlan{
		RunID:          run.ID,
		TemplateID:     run.TemplateID,
		ProjectID:      run.ProjectID,
		ScopeID:        run.ScopeID,
		TaskType:       run.TaskType,
		Targets:        config.Targets,
		RateLimit:      run.RateLimit,
		Concurrency:    run.Concurrency,
		TimeoutSeconds: run.TimeoutSeconds,
		RetryLimit:     run.RetryLimit,
		Options:        config.Options,
	}, nil
}

// DispatchTaskRun sends a pending run to the configured engine and records the
// returned engine_job_id. Callback handling and result ingest are owned by M2-5.
func (s *Service) DispatchTaskRun(ctx context.Context, in DispatchTaskRunInput) (*TaskRun, error) {
	if s.engine == nil {
		return nil, ErrEngineNotConfigured
	}
	plan, err := s.BuildDispatchPlan(ctx, in.ProjectID, in.RunID, in.ActorID)
	if err != nil {
		return nil, err
	}

	job := scanJobFromDispatchPlan(plan, in.CallbackURL)
	var lastErr error
	maxAttempts := plan.RetryLimit + 1
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := s.repo.IncrementRunAttempt(ctx, in.ProjectID, in.RunID, in.ActorID, s.nowFn()); err != nil {
			return nil, err
		}
		engineJobID, err := s.engine.Dispatch(ctx, job)
		if err == nil {
			run, recordErr := s.recordRunDispatched(ctx, in, engineJobID)
			if recordErr != nil {
				_ = s.engine.Cancel(ctx, engineJobID)
				return nil, recordErr
			}
			return run, nil
		}
		lastErr = err
	}

	summary := "engine dispatch failed"
	if lastErr != nil {
		summary = lastErr.Error()
	}
	run, err := s.recordRunDispatchFailed(ctx, in, summary)
	if err != nil {
		return nil, err
	}
	return run, lastErr
}

// CancelDispatchedTaskRun cancels a running engine job and records run cancellation.
func (s *Service) CancelDispatchedTaskRun(ctx context.Context, in UpdateTaskRunStatusInput) error {
	if s.engine == nil {
		return ErrEngineNotConfigured
	}
	if in.ProjectID == 0 || in.RunID == 0 {
		return ErrInvalidTaskRunID
	}
	if in.ActorID == "" || len(in.ActorID) > maxActorLen {
		return ErrInvalidActorID
	}
	run, err := s.repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
	if err != nil {
		return err
	}
	if run.Status != TaskRunStatusRunning || strings.TrimSpace(run.EngineJobID) == "" {
		return ErrInvalidRunTransition
	}
	if err := s.engine.Cancel(ctx, run.EngineJobID); err != nil {
		return err
	}
	return s.MarkTaskRunCancelled(ctx, in)
}

// ReconcileTaskRun pulls the external engine state for one running run and
// closes terminal engine jobs in the local state machine.
func (s *Service) ReconcileTaskRun(ctx context.Context, in ReconcileTaskRunInput) (*TaskRun, error) {
	if s.engine == nil {
		return nil, ErrEngineNotConfigured
	}
	if in.ProjectID == 0 || in.RunID == 0 {
		return nil, ErrInvalidTaskRunID
	}
	if in.ActorID == "" || len(in.ActorID) > maxActorLen {
		return nil, ErrInvalidActorID
	}
	run, err := s.repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
	if err != nil {
		return nil, err
	}
	return s.reconcileRun(ctx, run, in.ActorID, in.Meta, false)
}

// ReconcileTimedOutRuns recovers running runs whose dispatch deadline has passed.
func (s *Service) ReconcileTimedOutRuns(ctx context.Context, in ReconcileTimedOutRunsInput) (ReconcileTimedOutRunsResult, error) {
	if s.engine == nil {
		return ReconcileTimedOutRunsResult{}, ErrEngineNotConfigured
	}
	if in.ActorID == "" || len(in.ActorID) > maxActorLen {
		return ReconcileTimedOutRunsResult{}, ErrInvalidActorID
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 100
	}
	runs, err := s.repo.ListRunningRunsForReconcile(ctx, limit)
	if err != nil {
		return ReconcileTimedOutRunsResult{}, err
	}
	now := s.nowFn()
	result := ReconcileTimedOutRunsResult{}
	for _, run := range runs {
		if !runTimedOut(run, now) {
			continue
		}
		result.Checked++
		after, err := s.reconcileRun(ctx, run, in.ActorID, in.Meta, true)
		if err != nil {
			result.Errors = append(result.Errors, err)
			continue
		}
		if after != nil && after.Status != TaskRunStatusRunning {
			result.Updated++
			if after.Status == TaskRunStatusFailed && strings.Contains(after.ErrorSummary, "timed out") {
				result.Cancelled++
			}
		}
	}
	if len(result.Errors) > 0 {
		return result, errors.Join(result.Errors...)
	}
	return result, nil
}

func (s *Service) reconcileRun(ctx context.Context, run *TaskRun, actorID string, meta AuditMeta, timeoutMode bool) (*TaskRun, error) {
	if run.Status != TaskRunStatusRunning || strings.TrimSpace(run.EngineJobID) == "" {
		return nil, ErrInvalidRunTransition
	}
	status, err := s.engine.Status(ctx, run.EngineJobID)
	if err != nil {
		return nil, err
	}
	switch status.Status {
	case EngineJobStatusSuccess:
		return s.recordRunStatus(ctx, run.ProjectID, run.ID, actorID, TaskRunStatusSuccess, status.ResultCount, status.ErrorSummary, meta)
	case EngineJobStatusPartialSuccess:
		return s.recordRunStatus(ctx, run.ProjectID, run.ID, actorID, TaskRunStatusPartial, status.ResultCount, status.ErrorSummary, meta)
	case EngineJobStatusFailed:
		return s.recordRunStatus(ctx, run.ProjectID, run.ID, actorID, TaskRunStatusFailed, status.ResultCount, status.ErrorSummary, meta)
	case EngineJobStatusCancelled:
		return s.recordRunStatus(ctx, run.ProjectID, run.ID, actorID, TaskRunStatusCancelled, status.ResultCount, status.ErrorSummary, meta)
	case EngineJobStatusRunning:
		if timeoutMode {
			if err := s.engine.Cancel(ctx, run.EngineJobID); err != nil {
				return nil, err
			}
			return s.recordRunStatus(ctx, run.ProjectID, run.ID, actorID, TaskRunStatusFailed, run.ResultCount, "task run timed out", meta)
		}
		return run, nil
	default:
		return nil, ErrEngineStatus
	}
}

func (s *Service) recordRunStatus(ctx context.Context, projectID, runID uint64, actorID, status string, resultCount uint64, summary string, meta AuditMeta) (*TaskRun, error) {
	var after *TaskRun
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetTaskRun(ctx, projectID, runID)
		if err != nil {
			return err
		}
		in := UpdateTaskRunStatusInput{
			ProjectID:    projectID,
			RunID:        runID,
			ActorID:      actorID,
			ResultCount:  resultCount,
			ErrorSummary: summary,
			Meta:         meta,
		}
		if err := changeTaskRunStatusWith(ctx, repo, before, in, status, s.nowFn()); err != nil {
			return err
		}
		after, err = repo.GetTaskRun(ctx, projectID, runID)
		if err != nil {
			return err
		}
		return s.recordAuditWithSink(ctx, txAudit, ActionRunStatusChange, before, after, actorID, meta)
	})
	return after, err
}

func runTimedOut(run *TaskRun, now time.Time) bool {
	if run == nil || run.TimeoutSeconds <= 0 || run.DispatchedAt.IsZero() {
		return false
	}
	return !run.DispatchedAt.Add(time.Duration(run.TimeoutSeconds) * time.Second).After(now)
}

func scanJobFromDispatchPlan(plan *DispatchPlan, callbackURL string) ScanJob {
	targets := make([]Target, 0, len(plan.Targets))
	for _, target := range plan.Targets {
		targets = append(targets, Target(target))
	}
	return ScanJob{
		RunID:       strconv.FormatUint(plan.RunID, 10),
		JobType:     plan.TaskType,
		Targets:     targets,
		RateLimit:   plan.RateLimit,
		Concurrency: plan.Concurrency,
		Timeout:     time.Duration(plan.TimeoutSeconds) * time.Second,
		CallbackURL: callbackURL,
		Options:     plan.Options,
	}
}

func (s *Service) recordRunDispatched(ctx context.Context, in DispatchTaskRunInput, engineJobID string) (*TaskRun, error) {
	var after *TaskRun
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
		if err != nil {
			return err
		}
		if before.Status != TaskRunStatusPending {
			return ErrInvalidRunTransition
		}
		if err := repo.MarkRunDispatched(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, engineJobID, s.nowFn()); err != nil {
			return err
		}
		after, err = repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
		if err != nil {
			return err
		}
		return s.recordAuditWithSink(ctx, txAudit, ActionRunStatusChange, before, after, in.ActorID, in.Meta)
	})
	return after, err
}

func (s *Service) recordRunDispatchFailed(ctx context.Context, in DispatchTaskRunInput, summary string) (*TaskRun, error) {
	var after *TaskRun
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
		if err != nil {
			return err
		}
		if before.Status != TaskRunStatusPending {
			return ErrInvalidRunTransition
		}
		if err := repo.MarkRunDispatchFailed(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, summary, s.nowFn()); err != nil {
			return err
		}
		after, err = repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
		if err != nil {
			return err
		}
		return s.recordAuditWithSink(ctx, txAudit, ActionRunStatusChange, before, after, in.ActorID, in.Meta)
	})
	return after, err
}

// MarkTaskRunRunning transitions pending -> running.
func (s *Service) MarkTaskRunRunning(ctx context.Context, in UpdateTaskRunStatusInput) error {
	return s.changeTaskRunStatus(ctx, in, ActionRunStatusChange, TaskRunStatusRunning)
}

// MarkTaskRunSucceeded transitions running -> success.
func (s *Service) MarkTaskRunSucceeded(ctx context.Context, in UpdateTaskRunStatusInput) error {
	return s.changeTaskRunStatus(ctx, in, ActionRunStatusChange, TaskRunStatusSuccess)
}

// MarkTaskRunPartialSuccess transitions running -> partial_success.
func (s *Service) MarkTaskRunPartialSuccess(ctx context.Context, in UpdateTaskRunStatusInput) error {
	return s.changeTaskRunStatus(ctx, in, ActionRunStatusChange, TaskRunStatusPartial)
}

// MarkTaskRunFailed transitions running -> failed.
func (s *Service) MarkTaskRunFailed(ctx context.Context, in UpdateTaskRunStatusInput) error {
	return s.changeTaskRunStatus(ctx, in, ActionRunStatusChange, TaskRunStatusFailed)
}

// MarkTaskRunCancelled transitions pending|running -> cancelled.
func (s *Service) MarkTaskRunCancelled(ctx context.Context, in UpdateTaskRunStatusInput) error {
	return s.changeTaskRunStatus(ctx, in, ActionRunCancel, TaskRunStatusCancelled)
}

// IncrementTaskRunAttempt increments one run attempt count.
func (s *Service) IncrementTaskRunAttempt(ctx context.Context, in IncrementTaskRunAttemptInput) error {
	if in.ProjectID == 0 || in.RunID == 0 {
		return ErrInvalidTaskRunID
	}
	if in.ActorID == "" || len(in.ActorID) > maxActorLen {
		return ErrInvalidActorID
	}
	return s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		_ = txAudit
		if _, err := repo.GetTaskRun(ctx, in.ProjectID, in.RunID); err != nil {
			return err
		}
		now := s.nowFn()
		if err := repo.IncrementRunAttempt(ctx, in.ProjectID, in.RunID, in.ActorID, now); err != nil {
			return err
		}
		return nil
	})
}

func (s *Service) changeTaskRunStatus(ctx context.Context, in UpdateTaskRunStatusInput, action, targetStatus string) error {
	if in.ProjectID == 0 || in.RunID == 0 {
		return ErrInvalidTaskRunID
	}
	if _, err := validateTaskStatus(targetStatus); err != nil {
		return err
	}
	if in.ActorID == "" || len(in.ActorID) > maxActorLen {
		return ErrInvalidActorID
	}

	return s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
		if err != nil {
			return err
		}
		if err := changeTaskRunStatusWith(ctx, repo, before, in, targetStatus, s.nowFn()); err != nil {
			return err
		}

		after, err := repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
		if err != nil {
			return err
		}
		if action == "" {
			action = ActionRunStatusChange
		}
		return s.recordAuditWithSink(ctx, txAudit, action, before, after, in.ActorID, in.Meta)
	})
}

func changeTaskRunStatusWith(ctx context.Context, repo Repository, before *TaskRun, in UpdateTaskRunStatusInput, targetStatus string, now time.Time) error {
	if !isTaskRunTransitionAllowed(before.Status, targetStatus) {
		return ErrInvalidRunTransition
	}
	switch targetStatus {
	case TaskRunStatusRunning:
		return repo.MarkRunRunning(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, now)
	case TaskRunStatusSuccess:
		return repo.MarkRunSucceeded(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, in.ResultCount, now)
	case TaskRunStatusPartial:
		return repo.MarkRunPartialSuccess(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, in.ResultCount, now)
	case TaskRunStatusFailed:
		return repo.MarkRunFailed(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, in.ErrorSummary, in.ResultCount, now)
	case TaskRunStatusCancelled:
		return repo.MarkRunCancelled(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, in.ErrorSummary, now)
	default:
		return ErrInvalidRunTransition
	}
}

func isTaskRunTransitionAllowed(from, to string) bool {
	nexts, ok := validRunTransitions[from]
	if !ok {
		return false
	}
	return nexts[to]
}

func (s *Service) recordAudit(ctx context.Context, action string, before, after any, actorID string, meta AuditMeta) error {
	return s.recordAuditWithSink(ctx, s.auditSink, action, before, after, actorID, meta)
}

func (s *Service) recordAuditWithSink(ctx context.Context, sink auditRecorder, action string, before, after any, actorID string, meta AuditMeta) error {
	if sink == nil {
		return nil
	}
	if action != ActionScopeCreate &&
		action != ActionScopeUpdate &&
		action != ActionScopeDeactivate &&
		action != ActionTemplateCreate &&
		action != ActionTemplateUpdate &&
		action != ActionTemplateDelete &&
		action != ActionTemplateEnable &&
		action != ActionRunCreate &&
		action != ActionRunStatusChange &&
		action != ActionRunCancel {
		return ErrInvalidTemplateAction
	}

	entity, resourceType, err := extractAuditEntity(before, after)
	if err != nil {
		return err
	}

	return sink.Record(ctx, audit.Event{
		TenantID:     entity.tenantID,
		OrgID:        entity.orgID,
		ProjectID:    entity.projectID,
		ActorID:      actorID,
		ActorType:    audit.ActorUser,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   fmt.Sprintf("%d", entity.resourceID),
		Result:       audit.ResultSuccess,
		IP:           meta.IP,
		UserAgent:    meta.UserAgent,
		RequestID:    meta.RequestID,
		Before:       before,
		After:        after,
		Metadata:     meta,
	})
}

type auditEntity struct {
	resourceID uint64
	projectID  uint64
	tenantID   string
	orgID      string
}

func extractAuditEntity(before any, after any) (auditEntity, string, error) {
	var entity auditEntity
	switch v := before.(type) {
	case *Scope:
		if v != nil {
			entity = auditEntity{
				resourceID: v.ID,
				projectID:  v.ProjectID,
				tenantID:   v.TenantID,
				orgID:      v.OrgID,
			}
			return entity, ResourceTypeScope, nil
		}
	case *TaskTemplate:
		if v != nil {
			entity = auditEntity{
				resourceID: v.ID,
				projectID:  v.ProjectID,
				tenantID:   v.TenantID,
				orgID:      v.OrgID,
			}
			return entity, ResourceTypeTaskTemplate, nil
		}
	case *TaskRun:
		if v != nil {
			entity = auditEntity{
				resourceID: v.ID,
				projectID:  v.ProjectID,
				tenantID:   v.TenantID,
				orgID:      v.OrgID,
			}
			return entity, ResourceTypeTaskRun, nil
		}
	}

	switch v := after.(type) {
	case *Scope:
		if v != nil {
			entity = auditEntity{
				resourceID: v.ID,
				projectID:  v.ProjectID,
				tenantID:   v.TenantID,
				orgID:      v.OrgID,
			}
			return entity, ResourceTypeScope, nil
		}
	case *TaskTemplate:
		if v != nil {
			entity = auditEntity{
				resourceID: v.ID,
				projectID:  v.ProjectID,
				tenantID:   v.TenantID,
				orgID:      v.OrgID,
			}
			return entity, ResourceTypeTaskTemplate, nil
		}
	case *TaskRun:
		if v != nil {
			entity = auditEntity{
				resourceID: v.ID,
				projectID:  v.ProjectID,
				tenantID:   v.TenantID,
				orgID:      v.OrgID,
			}
			return entity, ResourceTypeTaskRun, nil
		}
	}

	return entity, "", ErrInvalidTemplate
}
