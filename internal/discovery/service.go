package discovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var (
	ErrInvalidScopeAction    = errors.New("discovery: invalid scope action")
	ErrInvalidTemplateAction = errors.New("discovery: invalid template action")
	ErrInvalidRunTransition  = errors.New("discovery: invalid task run transition")
)

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
	repo      Repository
	db        *sql.DB
	auditSink auditRecorder
	nowFn     func() time.Time
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
		if !isTaskRunTransitionAllowed(before.Status, targetStatus) {
			return ErrInvalidRunTransition
		}

		now := s.nowFn()
		switch targetStatus {
		case TaskRunStatusRunning:
			if err := repo.MarkRunRunning(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, now); err != nil {
				return err
			}
		case TaskRunStatusSuccess:
			if err := repo.MarkRunSucceeded(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, in.ResultCount, now); err != nil {
				return err
			}
		case TaskRunStatusPartial:
			if err := repo.MarkRunPartialSuccess(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, in.ResultCount, now); err != nil {
				return err
			}
		case TaskRunStatusFailed:
			if err := repo.MarkRunFailed(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, in.ErrorSummary, in.ResultCount, now); err != nil {
				return err
			}
		case TaskRunStatusCancelled:
			if err := repo.MarkRunCancelled(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, in.ErrorSummary, now); err != nil {
				return err
			}
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
