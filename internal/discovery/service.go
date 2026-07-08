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
	ErrInvalidScopeAction = errors.New("discovery: invalid scope action")
)

// Service applies the M2-1 scope authorization rules and writes audit events for
// mutating operations.
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

// WithDB enables transaction boundaries for mutating scope APIs.
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

// NewService builds the discovery scope service.
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
		return s.recordAuditWithSink(ctx, txAudit, ActionScopeCreate, nil, scope, in.ActorID, in.Meta)
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
// Downstream engine layers can use this reason for explicit decisions and audit.
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

func (s *Service) recordAudit(ctx context.Context, action string, before, after *Scope, actorID string, meta AuditMeta) error {
	return s.recordAuditWithSink(ctx, s.auditSink, action, before, after, actorID, meta)
}

func (s *Service) recordAuditWithSink(ctx context.Context, sink auditRecorder, action string, before, after *Scope, actorID string, meta AuditMeta) error {
	if sink == nil {
		return nil
	}
	if action != ActionScopeCreate && action != ActionScopeUpdate && action != ActionScopeDeactivate {
		return ErrInvalidScopeAction
	}
	scope := after
	if scope == nil {
		scope = before
	}
	resourceID := ""
	projectID := uint64(0)
	tenantID := ""
	orgID := ""
	if scope != nil {
		resourceID = fmt.Sprintf("%d", scope.ID)
		projectID = scope.ProjectID
		tenantID = scope.TenantID
		orgID = scope.OrgID
	}

	return sink.Record(ctx, audit.Event{
		TenantID:     tenantID,
		OrgID:        orgID,
		ProjectID:    projectID,
		ActorID:      actorID,
		ActorType:    audit.ActorUser,
		Action:       action,
		ResourceType: ResourceTypeScope,
		ResourceID:   resourceID,
		Result:       audit.ResultSuccess,
		IP:           meta.IP,
		UserAgent:    meta.UserAgent,
		RequestID:    meta.RequestID,
		Before:       before,
		After:        after,
		Metadata:     meta,
	})
}
