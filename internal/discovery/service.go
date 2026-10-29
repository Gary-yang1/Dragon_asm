//revive:disable:exported

package discovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/db"
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
	engineSettings      *EngineSettingsStore
	engineConfigVersion uint64
	repo                Repository
	db                  *sql.DB
	engine              EngineAdapter
	engineRouter        EngineSelector
	dispatchEnqueuer    DispatchEnqueuer
	assetMissThreshold  uint32
	callbackEnqueuer    CallbackEnqueuer
	callbackSecretRef   string
	auditSink           auditRecorder
	nowFn               func() time.Time
	// sleepFn gates dispatch retry backoff. Tests inject a no-op so they do not
	// pay real wall-clock delays.
	sleepFn func(ctx context.Context, d time.Duration) bool
	// ownership gates active scanning on proven domain control.
	ownership OwnershipChecker
	// activePolicy is fail-closed by default and must be set identically in the
	// API and Worker processes.
	activePolicy ActiveDispatchPolicy
	// activeResultIngestFn is the transaction boundary for one normalized result
	// page. Tests replace it with an in-memory sink; production uses MySQL.
	activeResultIngestFn activeResultIngestFunc
}

// WithOwnershipChecker supplies the verified-domain-ownership lookup used to gate
// active scanning. Without it, active task types are refused.
func WithOwnershipChecker(checker OwnershipChecker) ServiceOption {
	return func(s *Service) { s.ownership = checker }
}

// WithActiveDispatchPolicy configures the release gates around active tasks.
// It cannot disable unconditional Scope, dangerous-address, project, limit,
// audit, or nopoc safeguards.
func WithActiveDispatchPolicy(policy ActiveDispatchPolicy) ServiceOption {
	return func(s *Service) { s.activePolicy = policy }
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

// WithEngineRouter injects task-type-aware passive/active engine routing.
func WithEngineRouter(router EngineSelector) ServiceOption {
	return func(s *Service) {
		s.engineRouter = router
	}
}

// WithDispatchEnqueuer injects the producer used by manual TaskRun creation.
func WithDispatchEnqueuer(enqueuer DispatchEnqueuer) ServiceOption {
	return func(s *Service) {
		s.dispatchEnqueuer = enqueuer
	}
}

// WithCallbackEnqueuer injects the worker queue producer used by callback ingest.
func WithCallbackEnqueuer(enqueuer CallbackEnqueuer) ServiceOption {
	return func(s *Service) {
		s.callbackEnqueuer = enqueuer
	}
}

// WithCallbackSecretRef snapshots the configured engine identity on new runs.
// It is a reference only; secret material is never persisted with TaskRun.
func WithCallbackSecretRef(ref string) ServiceOption {
	return func(s *Service) {
		s.callbackSecretRef = strings.TrimSpace(ref)
	}
}

// WithNow overrides time source for deterministic tests.
func WithNow(now func() time.Time) ServiceOption {
	return func(s *Service) {
		s.nowFn = now
	}
}

// WithRetrySleep overrides the dispatch retry backoff. The function must report
// false when the wait was cut short by context cancellation.
func WithRetrySleep(sleep func(ctx context.Context, d time.Duration) bool) ServiceOption {
	return func(s *Service) {
		if sleep != nil {
			s.sleepFn = sleep
		}
	}
}

func WithAssetMissThreshold(threshold int) ServiceOption {
	return func(s *Service) {
		if threshold < 1 {
			return
		}
		if threshold > 1000 {
			threshold = 1000
		}
		s.assetMissThreshold = uint32(threshold) // #nosec G115 -- clamped to 1..1000
	}
}

// NewService builds the discovery service.
func NewService(repo Repository, opts ...ServiceOption) *Service {
	s := &Service{
		repo:               repo,
		assetMissThreshold: 3,
		nowFn:              func() time.Time { return time.Now().UTC() },
		activePolicy:       DefaultActiveDispatchPolicy(),
	}
	for _, opt := range opts {
		opt(s)
	}
	s.activeResultIngestFn = s.ingestActiveResultPayload
	return s
}

func (s *Service) hasEngineRouting() bool {
	return s.engineSettings != nil || s.engineRouter != nil || s.engine != nil
}

func (s *Service) engineForTaskType(taskType string) (EngineAdapter, error) {
	if s.engineRouter != nil {
		engine, err := s.engineRouter.EngineForTaskType(taskType)
		return s.withProjectResolver(engine), err
	}
	// Preserve the single-adapter option for existing embedders and focused
	// tests. Runtime wiring uses WithEngineRouter, so production never falls back
	// across passive and active routes.
	if s.engine != nil {
		return s.withProjectResolver(s.engine), nil
	}
	return nil, ErrEngineNotConfigured
}

func (s *Service) withProjectResolver(engine EngineAdapter) EngineAdapter {
	if active, ok := engine.(*ActiveAPIEngineAdapter); ok && s.db != nil && active.projectResolver == nil {
		copy := *active
		copy.projectResolver = &sqlEngineProjectResolver{db: s.db}
		return &copy
	}
	return engine
}

// validateEngineProject checks local routing without contacting an engine.
func (s *Service) validateEngineProject(projectID uint64, taskType string) error {
	engine, err := s.engineForTaskType(taskType)
	if err != nil {
		return err
	}
	if active, ok := engine.(*ActiveAPIEngineAdapter); ok {
		if active.projectIDs[projectID] <= 0 && active.projectResolver == nil {
			return ErrActiveEngineProjectMapping
		}
	}
	return nil
}

func (s *Service) requireActiveDispatchEnabled(taskType string) error {
	if IsActiveTaskType(taskType) && !s.activePolicy.Enabled {
		return ErrTaskTypeUnsupported
	}
	return nil
}

// runInTx runs fn in one transaction, re-running it if InnoDB rolls it back for a
// deadlock or lock-wait timeout.
//
// Callback ingest needs this: several callbacks for the same run are processed
// concurrently, and each transaction locks its own inbox row before locking every
// row of the run, so one of them loses a deadlock. Treating that as fatal left the
// callback stuck in `processing` — the run was then timed out by the reconcile
// worker even though the scan had actually succeeded.
//
// fn re-reads its state on every attempt, which is what makes re-running safe.
func (s *Service) runInTx(ctx context.Context, fn func(ctx context.Context, repo Repository, auditSink auditRecorder) error) error {
	if s.db == nil {
		return fn(ctx, s.repo, s.auditSink)
	}
	return db.RetryOnLockConflict(ctx, func() error {
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
	})
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
	if in.IsDefault && status != StatusActive {
		return nil, ErrInvalidDefaultScope
	}

	var scopeID uint64
	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		if in.IsDefault {
			if err := s.replaceProjectDefault(
				ctx, repo, txAudit, in.ProjectID, 0, in.ActorID, s.nowFn(), in.Meta,
			); err != nil {
				return err
			}
		}
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
			IsDefault:    in.IsDefault,
			ActorID:      in.ActorID,
		})
		if err != nil {
			return err
		}

		for _, t := range targets {
			if err := repo.InsertScopeTarget(ctx, InsertScopeTargetParams{
				TenantID:     in.TenantID,
				OrgID:        in.OrgID,
				ProjectID:    in.ProjectID,
				ScopeID:      scopeID,
				TargetType:   t.TargetType,
				MatchMode:    t.MatchMode,
				CoverageMode: t.CoverageMode,
				URLRule:      t.URLRule,
				Value:        t.Value,
				ActorID:      in.ActorID,
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
		if err := repo.LockProjectForScopeDefault(ctx, in.ProjectID); err != nil {
			return err
		}
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
		isDefault := before.IsDefault
		if in.IsDefault != nil {
			isDefault = *in.IsDefault
		}
		if status != StatusActive {
			if in.IsDefault != nil && *in.IsDefault {
				return ErrInvalidDefaultScope
			}
			isDefault = false
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

		if isDefault {
			if err := s.replaceProjectDefault(
				ctx, repo, txAudit, in.ProjectID, in.ScopeID, in.ActorID, s.nowFn(), in.Meta,
			); err != nil {
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
			IsDefault:    isDefault,
			ActorID:      in.ActorID,
		}); err != nil {
			return err
		}

		if in.Targets != nil {
			for _, t := range targets {
				if err := repo.InsertScopeTarget(ctx, InsertScopeTargetParams{
					TenantID:     in.TenantID,
					OrgID:        in.OrgID,
					ProjectID:    in.ProjectID,
					ScopeID:      in.ScopeID,
					TargetType:   t.TargetType,
					MatchMode:    t.MatchMode,
					CoverageMode: t.CoverageMode,
					URLRule:      t.URLRule,
					Value:        t.Value,
					ActorID:      in.ActorID,
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

// replaceProjectDefault serializes one project's default transfer and audits
// the displaced Scope in the same transaction. The database unique key remains
// the final concurrency guard; the project row lock makes the chosen winner
// deterministic before either request clears or assigns the marker.
func (s *Service) replaceProjectDefault(
	ctx context.Context,
	repo Repository,
	txAudit auditRecorder,
	projectID, exceptScopeID uint64,
	actorID string,
	updatedAt time.Time,
	meta AuditMeta,
) error {
	if err := repo.LockProjectForScopeDefault(ctx, projectID); err != nil {
		return err
	}

	var displaced []*Scope
	if txAudit != nil {
		scopes, err := repo.ListScopes(ctx, projectID)
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			if scope == nil || !scope.IsDefault || scope.ID == exceptScopeID {
				continue
			}
			targets, err := repo.ListScopeTargets(ctx, projectID, scope.ID)
			if err != nil {
				return err
			}
			before := *scope
			before.Targets = targets
			displaced = append(displaced, &before)
		}
	}

	if err := repo.ClearDefaultScopes(ctx, projectID, exceptScopeID, actorID, updatedAt); err != nil {
		return err
	}
	for _, before := range displaced {
		after := *before
		after.IsDefault = false
		after.UpdatedBy = actorID
		after.UpdatedAt = updatedAt
		if err := s.recordAuditWithSink(
			ctx, txAudit, ActionScopeUpdate, before, &after, actorID, meta,
		); err != nil {
			return err
		}
	}
	return nil
}

// DeactivateScope marks a live scope inactive.
func (s *Service) DeactivateScope(ctx context.Context, in DeactivateScopeInput) error {
	if in.ProjectID == 0 || in.ScopeID == 0 {
		return ErrInvalidScopeID
	}
	return s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		if err := repo.LockProjectForScopeDefault(ctx, in.ProjectID); err != nil {
			return err
		}
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
	scopes, err := s.repo.ListScopes(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for _, scope := range scopes {
		targets, err := s.repo.ListScopeTargets(ctx, projectID, scope.ID)
		if err != nil {
			return nil, err
		}
		scope.Targets = targets
	}
	return scopes, nil
}

// IsTargetAllowed validates time window + target policy and returns a reason.
//
// The target type is inferred from the value. Callers that already know it
// should use IsTypedTargetAllowed, which is the only way a company target can be
// matched.
func (s *Service) IsTargetAllowed(ctx context.Context, projectID, scopeID uint64, rawTarget string) (bool, ScopeRejectReason, error) {
	return s.IsTypedTargetAllowed(ctx, projectID, scopeID, "", rawTarget)
}

// IsTypedTargetAllowed validates time window + target policy for a target whose
// type the caller knows, and returns a reason.
func (s *Service) IsTypedTargetAllowed(ctx context.Context, projectID, scopeID uint64, targetType, rawTarget string) (bool, ScopeRejectReason, error) {
	if projectID == 0 || scopeID == 0 {
		return false, ReasonScopeNotFound, ErrInvalidScopeID
	}
	parsed, err := parseTypedTarget(targetType, rawTarget)
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

	decision := scopeMatchDecision(targets, parsed)
	return decision == ReasonAllowed, decision, nil
}

// CreateTaskTemplate creates a task template and validates scope ownership by project.
func (s *Service) CreateTaskTemplate(ctx context.Context, in CreateTaskTemplateInput) (*TaskTemplate, error) {
	if s.engineSettings != nil {
		scoped, err := s.withLatestSettings(ctx)
		if err != nil {
			return nil, err
		}
		return scoped.CreateTaskTemplate(ctx, in)
	}

	prepared, err := s.prepareTaskTemplateInput(in)
	if err != nil {
		return nil, err
	}
	in = prepared
	template := (*TaskTemplate)(nil)

	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		if _, err := repo.GetScope(ctx, in.ProjectID, in.ScopeID); err != nil {
			return err
		}
		validator := *s
		validator.repo = repo
		if err := validator.validateInheritedSnapshot(ctx, in.ProjectID, in.ScopeID, in.TaskType, in.Config); err != nil {
			return err
		}

		id, err := repo.CreateTaskTemplate(ctx, CreateTaskTemplateParams{
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

func (s *Service) prepareTaskTemplateInput(in CreateTaskTemplateInput) (CreateTaskTemplateInput, error) {
	if err := validateTemplateMeta(in.TenantID, in.OrgID, in.Name, in.ScopeID, in.ProjectID, in.TaskType, in.ActorID); err != nil {
		return CreateTaskTemplateInput{}, err
	}
	if err := s.requireActiveDispatchEnabled(in.TaskType); err != nil {
		return CreateTaskTemplateInput{}, err
	}
	if err := validateTemplateSchedule(in.Schedule); err != nil {
		return CreateTaskTemplateInput{}, err
	}
	config, err := normalizeTemplateConfig(in.Config)
	if err != nil {
		return CreateTaskTemplateInput{}, err
	}
	if err := validateActiveDispatchConfig(in.TaskType, config); err != nil {
		return CreateTaskTemplateInput{}, err
	}
	if err := validateTaskLimits(in.TimeoutSeconds, in.RateLimit, in.Concurrency, in.RetryLimit); err != nil {
		return CreateTaskTemplateInput{}, err
	}
	// Active probes carry much tighter ceilings than passive collection: the cost
	// of getting the rate wrong lands on someone else's servers.
	if err := ValidateActiveTaskLimits(in.TaskType, in.RateLimit, in.Concurrency); err != nil {
		return CreateTaskTemplateInput{}, err
	}
	in.Config = config
	return in, nil
}

// UpdateTaskTemplate updates fields but does not change scope association.
func (s *Service) UpdateTaskTemplate(ctx context.Context, in UpdateTaskTemplateInput) (*TaskTemplate, error) {
	if s.engineSettings != nil {
		scoped, err := s.withLatestSettings(ctx)
		if err != nil {
			return nil, err
		}
		return scoped.UpdateTaskTemplate(ctx, in)
	}

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

		if (hasInheritance(before.Config) && (in.Config != nil || in.TaskType != nil)) || (in.Config != nil && hasInheritance(*in.Config)) {
			return ErrInheritanceImmutable
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
		if err := s.requireActiveDispatchEnabled(taskType); err != nil {
			return err
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
		if err := validateActiveDispatchConfig(taskType, config); err != nil {
			return err
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
		if err := ValidateActiveTaskLimits(taskType, rateLimit, concurrency); err != nil {
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
	if s.engineSettings != nil {
		scoped, err := s.withLatestSettings(ctx)
		if err != nil {
			return nil, err
		}
		return scoped.SetTaskTemplateEnabled(ctx, in)
	}

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
		if in.Enabled {
			if _, err := validateTaskType(before.TaskType); err != nil {
				return err
			}
			if err := s.requireActiveDispatchEnabled(before.TaskType); err != nil {
				return err
			}
			if err := ValidateActiveTaskLimits(before.TaskType, before.RateLimit, before.Concurrency); err != nil {
				return err
			}
			if err := validateActiveDispatchConfig(before.TaskType, before.Config); err != nil {
				return err
			}
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
	if s.engineSettings != nil {
		scoped, err := s.withLatestSettings(ctx)
		if err != nil {
			return nil, err
		}
		return scoped.CreateTaskRun(ctx, in)
	}

	if in.ProjectID == 0 || in.TemplateID == 0 {
		return nil, ErrInvalidTemplateID
	}
	if in.ActorID == "" || len(in.ActorID) > maxActorLen {
		return nil, ErrInvalidActorID
	}
	if s.callbackSecretRef != "" && !validCallbackIdentity(s.callbackSecretRef) {
		return nil, ErrInvalidCallbackIdentity
	}
	var run *TaskRun

	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		template, err := repo.GetTaskTemplate(ctx, in.ProjectID, in.TemplateID)
		if err != nil {
			return err
		}
		validator := *s
		validator.repo = repo
		if err := validator.validateInheritedSnapshot(ctx, in.ProjectID, template.ScopeID, template.TaskType, template.Config); err != nil {
			return err
		}

		if !template.Enabled {
			return ErrTemplateDisabled
		}
		if _, err := validateTaskType(template.TaskType); err != nil {
			return err
		}
		if err := s.requireActiveDispatchEnabled(template.TaskType); err != nil {
			return err
		}
		if s.hasEngineRouting() {
			if err := s.validateEngineProject(in.ProjectID, template.TaskType); err != nil {
				return err
			}
		}
		if err := ValidateActiveTaskLimits(template.TaskType, template.RateLimit, template.Concurrency); err != nil {
			return err
		}
		if err := validateActiveDispatchConfig(template.TaskType, template.Config); err != nil {
			return err
		}
		// The task type lives on the template, so separation of duties can only be
		// checked once the template is loaded.
		if s.activePolicy.RequireApproval {
			if err := ValidateActiveApproval(template.TaskType, ActiveApproval{
				ActorID: in.ActorID, ApprovedBy: in.ApprovedBy,
			}); err != nil {
				return err
			}
		}
		id, err := repo.CreateTaskRun(ctx, CreateTaskRunParams{
			EngineConfigVersion: s.engineConfigVersion,
			TenantID:            template.TenantID,
			OrgID:               template.OrgID,
			ProjectID:           in.ProjectID,
			TemplateID:          in.TemplateID,
			ScopeID:             template.ScopeID,
			TaskType:            template.TaskType,
			Status:              TaskRunStatusPending,
			Progress:            0,
			TimeoutSeconds:      template.TimeoutSeconds,
			RateLimit:           template.RateLimit,
			Concurrency:         template.Concurrency,
			RetryLimit:          template.RetryLimit,
			Attempt:             0,
			EngineJobID:         "",
			DispatchedAt:        time.Time{},
			LastCallbackAt:      time.Time{},
			ResultCount:         0,
			CallbackSecretRef:   s.callbackSecretRef,
			ApprovedBy:          strings.TrimSpace(in.ApprovedBy),
			ApprovalReason:      strings.TrimSpace(in.ApprovalReason),
			ActorID:             in.ActorID,
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

// CreateAndEnqueueTaskRun creates a pending run and reliably hands it to the
// dispatch queue. A queue failure is fail-closed: the new run is cancelled and
// remains auditable instead of becoming an orphaned pending run.
func (s *Service) CreateAndEnqueueTaskRun(ctx context.Context, in CreateTaskRunInput) (*TaskRun, error) {
	run, err := s.CreateTaskRun(ctx, in)
	if err != nil {
		return nil, err
	}
	if s.dispatchEnqueuer != nil {
		err = s.dispatchEnqueuer.EnqueueTaskRun(ctx, DispatchTaskPayload{
			ProjectID: run.ProjectID,
			RunID:     run.ID,
			ActorID:   in.ActorID,
		})
	} else {
		err = ErrDispatchEnqueue
	}
	if err == nil {
		return run, nil
	}
	cancelErr := s.MarkTaskRunCancelled(ctx, UpdateTaskRunStatusInput{
		ProjectID:    run.ProjectID,
		RunID:        run.ID,
		ActorID:      in.ActorID,
		ErrorSummary: "dispatch queue unavailable",
		Meta:         in.Meta,
	})
	updated, getErr := s.GetTaskRun(ctx, run.ProjectID, run.ID)
	if getErr == nil {
		run = updated
	}
	return run, errors.Join(ErrDispatchEnqueue, err, cancelErr, getErr)
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
	if s.engineSettings != nil {
		scoped, err := s.withRunSettings(ctx, projectID, runID)
		if err != nil {
			return nil, err
		}
		return scoped.BuildDispatchPlan(ctx, projectID, runID, actorID)
	}

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
	if template.ProjectID != run.ProjectID ||
		template.ID != run.TemplateID ||
		template.ScopeID != run.ScopeID ||
		template.TaskType != run.TaskType {
		return nil, ErrInvalidTemplate
	}
	if !template.Enabled {
		return nil, ErrTemplateDisabled
	}
	if _, err := validateTaskType(run.TaskType); err != nil {
		return nil, err
	}
	if err := s.requireActiveDispatchEnabled(run.TaskType); err != nil {
		return nil, err
	}
	if err := ValidateActiveTaskLimits(run.TaskType, run.RateLimit, run.Concurrency); err != nil {
		return nil, err
	}
	if err := validateActiveDispatchConfig(run.TaskType, template.Config); err != nil {
		return nil, err
	}

	if err := s.validateInheritedSnapshot(ctx, projectID, run.ScopeID, run.TaskType, template.Config); err != nil {
		return nil, err
	}

	config, err := parseDispatchConfig(template.Config)
	if err != nil {
		return nil, err
	}
	for _, target := range config.Targets {
		allowed, reason, err := s.IsTypedTargetAllowed(ctx, projectID, run.ScopeID, target.Type, target.Value)
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

	// Scope membership says the operator listed the target; ownership says the
	// platform checked they control it. Active probing requires both, and this is
	// the last point before packets leave the building.
	if s.activePolicy.RequireOwnership {
		if err := s.requireVerifiedOwnership(ctx, projectID, run.TaskType, config.Targets); err != nil {
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

// requireVerifiedOwnership refuses an active run whose domain targets have no
// verified ownership proof in this project.
//
// It fails closed: with no checker configured, active scanning is refused rather
// than allowed, so a deployment that forgot to wire verification cannot probe.
func (s *Service) requireVerifiedOwnership(ctx context.Context, projectID uint64, taskType string, targets []DispatchTarget) error {
	if !IsActiveTaskType(taskType) {
		return nil
	}
	if s.ownership == nil {
		return ErrOwnershipRequired
	}
	for _, target := range targets {
		host := ownershipHostFor(target)
		if host == "" {
			// An active target the platform cannot attribute to a verified domain —
			// a bare IP or CIDR — has no ownership proof available, so it is refused.
			return ErrOwnershipRequired
		}
		verified, err := s.ownership.IsDomainOwnershipVerified(ctx, projectID, host)
		if err != nil {
			return err
		}
		if !verified {
			return ErrOwnershipRequired
		}
	}
	return nil
}

// ownershipHostFor reduces a target to the hostname whose ownership must be
// proven, or "" when no such attribution exists.
func ownershipHostFor(target DispatchTarget) string {
	value := strings.TrimSpace(target.Value)
	switch target.Type {
	case TargetTypeDomain:
		return value
	case TargetTypeURL:
		parsed, err := url.Parse(value)
		if err != nil {
			return ""
		}
		return parsed.Hostname()
	default:
		return ""
	}
}

// DispatchTaskRun sends a pending run to the configured engine and records the
// returned engine_job_id. Callback handling and result ingest are owned by M2-5.
func (s *Service) DispatchTaskRun(ctx context.Context, in DispatchTaskRunInput) (*TaskRun, error) {
	if s.engineSettings != nil {
		scoped, err := s.withRunSettings(ctx, in.ProjectID, in.RunID)
		if err != nil {
			return nil, err
		}
		return scoped.DispatchTaskRun(ctx, in)
	}

	if !s.hasEngineRouting() {
		return nil, ErrEngineNotConfigured
	}
	existing, err := s.repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
	if err != nil {
		return nil, err
	}
	if existing.Status == TaskRunStatusRunning && strings.TrimSpace(existing.EngineJobID) != "" {
		return existing, nil
	}
	if existing.Status != TaskRunStatusPending {
		return nil, ErrTaskRunNotDispatchable
	}
	plan, err := s.BuildDispatchPlan(ctx, in.ProjectID, in.RunID, in.ActorID)
	if err != nil {
		return nil, err
	}
	// Keep a dispatch-time capability check for historical rows that predate the
	// template validation guard. Release policy is checked separately below.
	if !IsDispatchableTaskType(plan.TaskType) {
		return nil, ErrTaskTypeUnsupported
	}
	if err := s.requireActiveDispatchEnabled(plan.TaskType); err != nil {
		return nil, err
	}
	engine, err := s.engineForTaskType(plan.TaskType)
	if err != nil {
		return nil, err
	}

	job := scanJobFromDispatchPlan(plan, in.CallbackURL)
	var lastErr error
	maxAttempts := plan.RetryLimit + 1
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// retry_limit is caller-supplied (up to 100), so without this the loop
		// keeps hammering the engine after the task's deadline has passed.
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}
		// Back off before every attempt but the first. Previously all 101 attempts
		// fired back to back, so one run could issue 101 immediate POSTs at the
		// engine — a self-inflicted burst exactly when it is already unhealthy.
		if attempt > 0 && !s.waitBeforeRetry(ctx, attempt) {
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			break
		}
		if err := s.repo.IncrementRunAttempt(ctx, in.ProjectID, in.RunID, in.ActorID, s.nowFn()); err != nil {
			return nil, err
		}
		engineJobID, err := engine.Dispatch(ctx, job)
		if err == nil {
			run, recordErr := s.recordRunDispatched(ctx, in, engineJobID)
			if recordErr != nil {
				current, currentErr := s.repo.GetTaskRun(ctx, in.ProjectID, in.RunID)
				if currentErr == nil && current.Status == TaskRunStatusRunning && current.EngineJobID == engineJobID {
					return current, nil
				}
				_ = engine.Cancel(ctx, engineJobID)
				return nil, recordErr
			}
			return run, nil
		}
		lastErr = err
		// A rejected payload or a 4xx means the engine refused this request on its
		// merits; the six task types that never reach the engine land here. Retrying
		// identical bytes cannot help, so fail fast instead of burning the budget.
		if dispatchErrorIsPermanent(err) {
			break
		}
	}

	summary := sanitizeEngineErrorSummary(lastErr, "engine dispatch failed")
	run, err := s.recordRunDispatchFailed(ctx, in, summary)
	if err != nil {
		return nil, err
	}
	return run, lastErr
}

// CancelDispatchedTaskRun cancels a pending or running run idempotently. Pending
// jobs need no engine call; running jobs are cancelled remotely before the local
// transition is committed.
func (s *Service) CancelDispatchedTaskRun(ctx context.Context, in UpdateTaskRunStatusInput) error {
	if s.engineSettings != nil {
		scoped, err := s.withRunSettings(ctx, in.ProjectID, in.RunID)
		if err != nil {
			return err
		}
		return scoped.CancelDispatchedTaskRun(ctx, in)
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
	switch run.Status {
	case TaskRunStatusCancelled:
		return nil
	case TaskRunStatusPending:
		return s.MarkTaskRunCancelled(ctx, in)
	case TaskRunStatusRunning:
		if strings.TrimSpace(run.EngineJobID) == "" {
			return ErrInvalidRunTransition
		}
		engine, err := s.engineForTaskType(run.TaskType)
		if err != nil {
			return err
		}
		if err := engine.Cancel(ctx, run.EngineJobID); err != nil {
			return err
		}
		return s.MarkTaskRunCancelled(ctx, in)
	default:
		return ErrInvalidRunTransition
	}
}

// ReconcileTaskRun pulls the external engine state for one running run and
// closes terminal engine jobs in the local state machine.
func (s *Service) ReconcileTaskRun(ctx context.Context, in ReconcileTaskRunInput) (*TaskRun, error) {
	if !s.hasEngineRouting() {
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

// ReconcileRunningRuns polls ordinary running jobs, pulls terminal active-engine
// results, and also applies timeout recovery when a deadline has elapsed.
func (s *Service) ReconcileRunningRuns(
	ctx context.Context,
	in ReconcileRunningRunsInput,
) (ReconcileTimedOutRunsResult, error) {
	if !s.hasEngineRouting() {
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
		result.Checked++
		timeoutMode := runTimedOut(run, now)
		after, err := s.reconcileRun(ctx, run, in.ActorID, in.Meta, timeoutMode)
		if err != nil {
			result.FailedRunIDs = append(result.FailedRunIDs, run.ID)
			result.Errors = append(result.Errors, err)
			continue
		}
		if after != nil && after.Status != TaskRunStatusRunning {
			result.Updated++
			if timeoutMode &&
				after.Status == TaskRunStatusFailed &&
				strings.Contains(after.ErrorSummary, "timed out") {
				result.Cancelled++
			}
		}
	}
	if len(result.Errors) > 0 {
		return result, errors.Join(result.Errors...)
	}
	return result, nil
}

// ReconcileTimedOutRuns recovers running runs whose dispatch deadline has passed.
func (s *Service) ReconcileTimedOutRuns(ctx context.Context, in ReconcileTimedOutRunsInput) (ReconcileTimedOutRunsResult, error) {
	if !s.hasEngineRouting() {
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
			result.FailedRunIDs = append(result.FailedRunIDs, run.ID)
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
	if s.engineSettings != nil {
		scoped, err := s.withRunSettings(ctx, run.ProjectID, run.ID)
		if err != nil {
			return nil, err
		}
		return scoped.reconcileRun(ctx, run, actorID, meta, timeoutMode)
	}

	if run.Status != TaskRunStatusRunning || strings.TrimSpace(run.EngineJobID) == "" {
		return nil, ErrInvalidRunTransition
	}
	engine, err := s.engineForTaskType(run.TaskType)
	if err != nil {
		return nil, err
	}
	status, err := engine.Status(ctx, run.EngineJobID)
	if err != nil {
		return nil, err
	}
	// A terminal engine status only means collection ended. Never close a
	// streaming run while acknowledged callback batches are still being ingested.
	if !IsActiveTaskType(run.TaskType) && (status.Status == EngineJobStatusSuccess || status.Status == EngineJobStatusPartialSuccess) {
		callbacks, callbackErr := s.repo.ListDiscoveryCallbacksForRunForUpdate(ctx, run.ProjectID, run.ID)
		if callbackErr != nil {
			return nil, callbackErr
		}
		if len(callbacks) > 0 {
			_, _, ready, callbackErr := callbackFinalState(callbacks)
			if callbackErr != nil {
				return nil, callbackErr
			}
			if !ready {
				if timeoutMode {
					return s.recordRunStatus(ctx, run.ProjectID, run.ID, actorID, TaskRunStatusFailed, run.ResultCount, "engine completed but result ingestion did not finish before timeout", meta)
				}
				return run, nil
			}
		}
	}
	resultCount := status.ResultCount
	activeResultLifecycle := false
	if IsActiveTaskType(run.TaskType) && status.Status != EngineJobStatusRunning {
		pulled, pullErr := s.pullActiveRunResults(ctx, run, engine)
		if pullErr != nil {
			return nil, pullErr
		}
		if status.Status == EngineJobStatusSuccess &&
			(pulled.FinishedTargets != pulled.TotalTargets ||
				pulled.TargetCount != pulled.TotalTargets) {
			return nil, ErrEngineResultIncomplete
		}
		resultCount = pulled.FactCount
		activeResultLifecycle = status.Status == EngineJobStatusSuccess ||
			status.Status == EngineJobStatusPartialSuccess
	}
	switch status.Status {
	case EngineJobStatusSuccess:
		return s.recordRunStatusWithLifecycle(
			ctx, run.ProjectID, run.ID, actorID, TaskRunStatusSuccess,
			resultCount, status.ErrorSummary, meta, activeResultLifecycle,
		)
	case EngineJobStatusPartialSuccess:
		return s.recordRunStatusWithLifecycle(
			ctx, run.ProjectID, run.ID, actorID, TaskRunStatusPartial,
			resultCount, status.ErrorSummary, meta, activeResultLifecycle,
		)
	case EngineJobStatusFailed:
		return s.recordRunStatus(
			ctx, run.ProjectID, run.ID, actorID, TaskRunStatusFailed,
			resultCount, status.ErrorSummary, meta,
		)
	case EngineJobStatusCancelled:
		return s.recordRunStatus(
			ctx, run.ProjectID, run.ID, actorID, TaskRunStatusCancelled,
			resultCount, status.ErrorSummary, meta,
		)
	case EngineJobStatusRunning:
		if timeoutMode {
			summary := "task run timed out"
			if err := engine.Cancel(ctx, run.EngineJobID); err != nil {
				// Local timeout closure is authoritative. Record the cancellation
				// failure without exposing the upstream error or leaving the run live.
				summary = "task run timed out; engine cancellation failed"
			}
			return s.recordRunStatus(ctx, run.ProjectID, run.ID, actorID, TaskRunStatusFailed, run.ResultCount, summary, meta)
		}
		return run, nil
	default:
		return nil, ErrEngineStatus
	}
}

// maxErrorSummaryLen matches task_run.error_summary VARCHAR(1024). The column
// counts characters, so the bound is on runes.
const maxErrorSummaryLen = 1024

// truncateErrorSummary bounds a summary to the column width without splitting a
// rune. The engine supplies this string and never bounds it, and in MySQL strict
// mode an over-long value fails the UPDATE — which leaves the run stuck in
// 'running' and makes the reconcile worker retry it on every tick, forever.
func truncateErrorSummary(summary string) string {
	runes := []rune(summary)
	if len(runes) <= maxErrorSummaryLen {
		return summary
	}
	return string(runes[:maxErrorSummaryLen])
}

// sanitizeEngineErrorSummary renders an engine failure for storage and display.
//
// A *url.Error stringifies as `Post "http://engine-internal:9090/scan": …`, and
// error_summary is echoed to every caller holding discovery:read via the run
// DTO. Unwrapping keeps the useful cause (`dial tcp: connection refused`) while
// dropping the internal endpoint.
func sanitizeEngineErrorSummary(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return truncateErrorSummary("engine dispatch failed: " + urlErr.Err.Error())
	}
	return truncateErrorSummary(err.Error())
}

func (s *Service) recordRunStatus(ctx context.Context, projectID, runID uint64, actorID, status string, resultCount uint64, summary string, meta AuditMeta) (*TaskRun, error) {
	return s.recordRunStatusWithLifecycle(
		ctx,
		projectID,
		runID,
		actorID,
		status,
		resultCount,
		summary,
		meta,
		false,
	)
}

func (s *Service) recordRunStatusWithLifecycle(
	ctx context.Context,
	projectID uint64,
	runID uint64,
	actorID string,
	status string,
	resultCount uint64,
	summary string,
	meta AuditMeta,
	applyLifecycle bool,
) (*TaskRun, error) {
	summary = truncateErrorSummary(summary)
	var after *TaskRun
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		before, err := repo.GetTaskRun(ctx, projectID, runID)
		if err != nil {
			return err
		}
		if before.Status == status {
			after = before
			return nil
		}
		if applyLifecycle && (status == TaskRunStatusSuccess || status == TaskRunStatusPartial) {
			if err := repo.ApplyDiscoveryObservationLifecycle(
				ctx,
				projectID,
				runID,
				capabilityForTaskType(before.TaskType),
				s.assetMissThreshold,
				status == TaskRunStatusSuccess,
				"engine",
				s.nowFn(),
			); err != nil {
				return err
			}
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
		RunID:       plan.RunID,
		ProjectID:   plan.ProjectID,
		ScopeID:     plan.ScopeID,
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
		if before.Status == TaskRunStatusRunning && before.EngineJobID == engineJobID {
			after = before
			return nil
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
		return repo.MarkRunPartialSuccess(ctx, in.ProjectID, in.RunID, in.ActorID, before.Status, in.ErrorSummary, in.ResultCount, now)
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

// Dispatch retry backoff bounds. The engine is a single owned service, so the goal
// is only to stop a run from hammering it: a short base with exponential growth
// and a hard ceiling.
const (
	dispatchRetryBaseDelay = 250 * time.Millisecond
	dispatchRetryMaxDelay  = 10 * time.Second
)

// waitBeforeRetry sleeps before attempt N, returning false if the context ended
// first so the caller stops retrying.
func (s *Service) waitBeforeRetry(ctx context.Context, attempt int) bool {
	delay := dispatchRetryBaseDelay << (attempt - 1)
	if delay > dispatchRetryMaxDelay || delay <= 0 {
		delay = dispatchRetryMaxDelay
	}
	if s.sleepFn != nil {
		return s.sleepFn(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// dispatchErrorIsPermanent reports whether another identical attempt is futile:
// the adapter refused the payload up front, or the engine answered 4xx. Transport
// faults and 5xx stay retryable.
func dispatchErrorIsPermanent(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrEngineJobRejected) {
		return true
	}
	var statusErr *engineStatusError
	if errors.As(err, &statusErr) {
		return statusErr.permanent()
	}
	return false
}
