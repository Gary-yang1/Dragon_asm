//revive:disable:exported

package ticket

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/Gary-yang1/Dragon_asm/internal/risk"
)

var (
	ErrInvalidProjectID     = errors.New("ticket: invalid project id")
	ErrInvalidTicketID      = errors.New("ticket: invalid ticket id")
	ErrInvalidRiskID        = errors.New("ticket: invalid risk id")
	ErrInvalidActorID       = errors.New("ticket: invalid actor id")
	ErrInvalidTitle         = errors.New("ticket: invalid title")
	ErrInvalidAssignee      = errors.New("ticket: invalid assignee")
	ErrInvalidPriority      = errors.New("ticket: invalid priority")
	ErrInvalidAction        = errors.New("ticket: invalid action")
	ErrInvalidTransition    = errors.New("ticket: invalid status transition")
	ErrResolutionRequired   = errors.New("ticket: resolution required")
	ErrRetestResultRequired = errors.New("ticket: retest_result required")
	ErrDueAtRequired        = errors.New("ticket: due_at required")
	ErrReasonRequired       = errors.New("ticket: reason required")
	ErrApprovedByRequired   = errors.New("ticket: approved_by required")
	ErrReviewWindowRequired = errors.New("ticket: review window required")
	ErrFieldTooLong         = errors.New("ticket: field too long")
)

type riskService interface {
	GetByID(ctx context.Context, projectID, id uint64) (*risk.Risk, error)
	TransitionStatus(ctx context.Context, in risk.StatusTransitionInput) (*risk.Risk, error)
	ResolveDueAt(ctx context.Context, projectID uint64, severity, businessUnit string, from time.Time) (time.Time, error)
}

type auditRecorder interface {
	Record(ctx context.Context, e audit.Event) error
}

type Service struct {
	repo      Repository
	db        *sql.DB
	risks     riskService
	auditSink auditRecorder
	now       func() time.Time
}

type ServiceOption func(*Service)

func WithDB(db *sql.DB) ServiceOption {
	return func(s *Service) { s.db = db }
}

func WithRiskService(risks riskService) ServiceOption {
	return func(s *Service) { s.risks = risks }
}

func WithAuditSink(sink auditRecorder) ServiceOption {
	return func(s *Service) { s.auditSink = sink }
}

func WithNow(fn func() time.Time) ServiceOption {
	return func(s *Service) {
		if fn != nil {
			s.now = fn
		}
	}
}

func NewService(repo Repository, opts ...ServiceOption) *Service {
	s := &Service{repo: repo, now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Service) Create(ctx context.Context, in CreateInput) (*Ticket, error) {
	if in.DueAt.IsZero() && s.risks != nil {
		dueAt, err := s.deriveTicketDueAt(ctx, in.ProjectID, in.RiskIDs)
		if err != nil {
			return nil, err
		}
		in.DueAt = dueAt
	}
	if err := validateCreate(in); err != nil {
		return nil, err
	}
	in.Priority = defaultString(strings.TrimSpace(in.Priority), PriorityMedium)
	var id uint64
	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, sink auditRecorder) error {
		var err error
		id, err = repo.Create(ctx, CreateParams{
			TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
			Title: strings.TrimSpace(in.Title), Description: strings.TrimSpace(in.Description),
			Assignee: strings.TrimSpace(in.Assignee), BusinessUnit: strings.TrimSpace(in.BusinessUnit),
			Status: StatusOpen, Priority: in.Priority, DueAt: in.DueAt,
			ExternalTicketID: strings.TrimSpace(in.ExternalTicketID), ActorID: in.ActorID,
		})
		if err != nil {
			return err
		}
		for _, riskID := range in.RiskIDs {
			if err := repo.LinkRisk(ctx, LinkRiskParams{
				TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
				TicketID: id, RiskID: riskID, ActorID: in.ActorID,
			}); err != nil {
				return err
			}
			if err := s.assignRisk(ctx, in.ProjectID, riskID, in.Assignee, in.DueAt, in.ActorID); err != nil {
				return err
			}
		}
		created, err := repo.GetByID(ctx, in.ProjectID, id)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sink, audit.Event{
			TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
			ActorID: in.ActorID, ActorType: audit.ActorUser, Action: ActionTicketCreate,
			ResourceType: ResourceTypeTicket, ResourceID: strconv.FormatUint(id, 10),
			After: created, Metadata: map[string]any{"risk_ids": in.RiskIDs},
		})
	}); err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, in.ProjectID, id)
}

func (s *Service) Transition(ctx context.Context, in TransitionInput) (*Ticket, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if in.TicketID == 0 {
		return nil, ErrInvalidTicketID
	}
	if in.ActorID == "" || len(in.ActorID) > 64 {
		return nil, ErrInvalidActorID
	}
	var out *Ticket
	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, sink auditRecorder) error {
		t, err := repo.GetByID(ctx, in.ProjectID, in.TicketID)
		if err != nil {
			return err
		}
		next, err := nextStatus(in.Action, t.Status)
		if err != nil {
			return err
		}
		if err := validateTransition(in, next); err != nil {
			return err
		}
		update := buildStatusUpdate(t, in, next, s.now())
		if err := repo.UpdateStatus(ctx, update); err != nil {
			return err
		}
		links, err := repo.ListRisks(ctx, in.ProjectID, in.TicketID)
		if err != nil {
			return err
		}
		for _, link := range links {
			if err := s.transitionLinkedRisk(ctx, link.RiskID, in, next, update); err != nil {
				return err
			}
		}
		after, err := repo.GetByID(ctx, in.ProjectID, in.TicketID)
		if err != nil {
			return err
		}
		out = after
		return s.recordAudit(ctx, sink, audit.Event{
			TenantID: t.TenantID, OrgID: t.OrgID, ProjectID: in.ProjectID,
			ActorID: in.ActorID, ActorType: audit.ActorUser, Action: ActionTicketStatusChange,
			ResourceType: ResourceTypeTicket, ResourceID: strconv.FormatUint(in.TicketID, 10),
			Before: t, After: after, Metadata: map[string]any{"action": in.Action, "from": t.Status, "to": after.Status},
		})
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) GetByID(ctx context.Context, projectID, id uint64) (*Ticket, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if id == 0 {
		return nil, ErrInvalidTicketID
	}
	return s.repo.GetByID(ctx, projectID, id)
}

func (s *Service) List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Ticket, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.List(ctx, projectID, limit, offset)
}

func (s *Service) Count(ctx context.Context, projectID uint64) (int64, error) {
	if projectID == 0 {
		return 0, ErrInvalidProjectID
	}
	return s.repo.Count(ctx, projectID)
}

func (s *Service) assignRisk(ctx context.Context, projectID, riskID uint64, assignee string, dueAt time.Time, actorID string) error {
	if s.risks == nil {
		return nil
	}
	r, err := s.risks.GetByID(ctx, projectID, riskID)
	if err != nil {
		return err
	}
	if r.Status == risk.StatusNew {
		if _, err := s.risks.TransitionStatus(ctx, risk.StatusTransitionInput{
			ProjectID: projectID, RiskID: riskID, Action: risk.StatusActionConfirm, ActorID: actorID,
		}); err != nil {
			return err
		}
		r.Status = risk.StatusConfirmed
	}
	if r.Status == risk.StatusConfirmed || r.Status == risk.StatusReopened {
		_, err = s.risks.TransitionStatus(ctx, risk.StatusTransitionInput{
			ProjectID: projectID, RiskID: riskID, Action: risk.StatusActionAssign, ActorID: actorID,
			Owner: assignee, SLADueAt: dueAt,
		})
		return err
	}
	return nil
}

func (s *Service) deriveTicketDueAt(ctx context.Context, projectID uint64, riskIDs []uint64) (time.Time, error) {
	var earliest time.Time
	for _, riskID := range riskIDs {
		r, err := s.risks.GetByID(ctx, projectID, riskID)
		if err != nil {
			return time.Time{}, err
		}
		from := r.FirstSeen
		if from.IsZero() {
			from = s.now()
		}
		dueAt, err := s.risks.ResolveDueAt(ctx, projectID, r.Severity, r.BusinessUnit, from)
		if err != nil {
			return time.Time{}, err
		}
		if earliest.IsZero() || dueAt.Before(earliest) {
			earliest = dueAt
		}
	}
	return earliest, nil
}

func (s *Service) transitionLinkedRisk(ctx context.Context, riskID uint64, in TransitionInput, next string, update StatusUpdateParams) error {
	if s.risks == nil {
		return nil
	}
	action := ""
	reason := ""
	switch next {
	case StatusInProgress:
		action = risk.StatusActionStartFix
		if update.OldStatus == StatusRejected {
			action = ""
		}
	case StatusResolved:
		action = risk.StatusActionMarkFixed
		reason = defaultString(update.Resolution, "ticket retest passed")
	case StatusClosed:
		action = risk.StatusActionMarkFixed
		reason = defaultString(update.Resolution, "ticket retest passed")
	case StatusRejected:
		action = ""
		reason = defaultString(update.RetestResult, "ticket retest rejected")
	case StatusCancelled:
		switch in.Action {
		case ActionAcceptRisk:
			action = risk.StatusActionAccept
			reason = in.Reason
		case ActionFalsePositive:
			action = risk.StatusActionFalsePositive
			reason = in.Reason
		}
	case StatusAssigned:
		return s.assignRisk(ctx, in.ProjectID, riskID, update.Assignee, update.DueAt, in.ActorID)
	}
	if action == "" {
		return nil
	}
	_, err := s.risks.TransitionStatus(ctx, risk.StatusTransitionInput{
		ProjectID: in.ProjectID, RiskID: riskID, Action: action, ActorID: in.ActorID,
		Reason: reason, ApprovedBy: in.ApprovedBy, ExpiresAt: in.ExpiresAt, ReviewRequiredAt: in.ReviewRequiredAt,
	})
	if errors.Is(err, risk.ErrInvalidStatusTransition) {
		return nil
	}
	return err
}

func (s *Service) runInTx(ctx context.Context, fn func(context.Context, Repository, auditRecorder) error) error {
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

func (s *Service) recordAudit(ctx context.Context, sink auditRecorder, event audit.Event) error {
	if sink == nil {
		return nil
	}
	return sink.Record(ctx, event)
}

func validateCreate(in CreateInput) error {
	if in.ProjectID == 0 {
		return ErrInvalidProjectID
	}
	if in.ActorID == "" || len(in.ActorID) > 64 {
		return ErrInvalidActorID
	}
	if strings.TrimSpace(in.Title) == "" || len(in.Title) > 255 {
		return ErrInvalidTitle
	}
	if strings.TrimSpace(in.Assignee) == "" || len(in.Assignee) > 64 {
		return ErrInvalidAssignee
	}
	if in.DueAt.IsZero() {
		return ErrDueAtRequired
	}
	if !validPriority(defaultString(in.Priority, PriorityMedium)) {
		return ErrInvalidPriority
	}
	if len(in.Description) > 2048 || len(in.BusinessUnit) > 128 || len(in.ExternalTicketID) > 128 {
		return ErrFieldTooLong
	}
	if len(in.RiskIDs) == 0 {
		return ErrInvalidRiskID
	}
	seen := map[uint64]struct{}{}
	for _, id := range in.RiskIDs {
		if id == 0 {
			return ErrInvalidRiskID
		}
		if _, ok := seen[id]; ok {
			return ErrInvalidRiskID
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateTransition(in TransitionInput, next string) error {
	switch next {
	case StatusAssigned:
		if strings.TrimSpace(in.Assignee) == "" {
			return ErrInvalidAssignee
		}
		if in.DueAt.IsZero() {
			return ErrDueAtRequired
		}
	case StatusResolved:
		if strings.TrimSpace(in.Resolution) == "" {
			return ErrResolutionRequired
		}
	case StatusClosed:
		if in.Action == ActionRetestPass && strings.TrimSpace(in.Resolution) == "" {
			return ErrResolutionRequired
		}
	case StatusRejected:
		if strings.TrimSpace(in.RetestResult) == "" {
			return ErrRetestResultRequired
		}
	case StatusCancelled:
		if in.Action == ActionAcceptRisk || in.Action == ActionFalsePositive {
			if strings.TrimSpace(in.Reason) == "" {
				return ErrReasonRequired
			}
			if strings.TrimSpace(in.ApprovedBy) == "" {
				return ErrApprovedByRequired
			}
			if in.ExpiresAt.IsZero() && in.ReviewRequiredAt.IsZero() {
				return ErrReviewWindowRequired
			}
		}
	case StatusExtended:
		if in.DueAt.IsZero() {
			return ErrDueAtRequired
		}
	}
	return nil
}

func nextStatus(action, current string) (string, error) {
	switch action {
	case ActionAssign:
		if current == StatusOpen {
			return StatusAssigned, nil
		}
	case ActionStart:
		if current == StatusAssigned || current == StatusRejected || current == StatusExtended {
			return StatusInProgress, nil
		}
	case ActionSubmitRetest:
		if current == StatusInProgress {
			return StatusPendingRetest, nil
		}
	case ActionRetestPass:
		if current == StatusPendingRetest {
			return StatusClosed, nil
		}
	case ActionClose:
		if current == StatusResolved {
			return StatusClosed, nil
		}
	case ActionRetestReject:
		if current == StatusPendingRetest {
			return StatusRejected, nil
		}
	case ActionAcceptRisk, ActionFalsePositive:
		if current == StatusPendingRetest {
			return StatusCancelled, nil
		}
	case ActionExtend:
		if current == StatusAssigned || current == StatusInProgress || current == StatusRejected {
			return StatusExtended, nil
		}
	case ActionCancel:
		if current != StatusClosed {
			return StatusCancelled, nil
		}
	default:
		return "", ErrInvalidAction
	}
	return "", ErrInvalidTransition
}

func buildStatusUpdate(t *Ticket, in TransitionInput, next string, now time.Time) StatusUpdateParams {
	assignee := t.Assignee
	if strings.TrimSpace(in.Assignee) != "" {
		assignee = strings.TrimSpace(in.Assignee)
	}
	dueAt := t.DueAt
	if !in.DueAt.IsZero() {
		dueAt = in.DueAt
	}
	closedAt := t.ClosedAt
	if next == StatusClosed || next == StatusCancelled {
		closedAt = now
	}
	return StatusUpdateParams{
		ProjectID: t.ProjectID, TicketID: t.ID, OldStatus: t.Status, NewStatus: next,
		Assignee: assignee, DueAt: dueAt, Resolution: strings.TrimSpace(in.Resolution),
		RetestResult: strings.TrimSpace(in.RetestResult), ClosedAt: closedAt, ActorID: in.ActorID,
	}
}

func validPriority(priority string) bool {
	switch priority {
	case PriorityUrgent, PriorityHigh, PriorityMedium, PriorityLow:
		return true
	default:
		return false
	}
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
