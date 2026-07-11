package ticket

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	"github.com/Gary-yang1/Dragon_asm/internal/risk"
)

type fakeRepo struct {
	tickets      map[uint64]*Ticket
	links        map[uint64][]*TicketRisk
	nextTicketID uint64
	nextLinkID   uint64
}

type fakeAudit struct {
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	f.events = append(f.events, e)
	return nil
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{tickets: map[uint64]*Ticket{}, links: map[uint64][]*TicketRisk{}, nextTicketID: 1, nextLinkID: 1}
}

func (f *fakeRepo) Create(_ context.Context, in CreateParams) (uint64, error) {
	id := f.nextTicketID
	f.nextTicketID++
	f.tickets[id] = &Ticket{
		ID: id, TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		Title: in.Title, Description: in.Description, Assignee: in.Assignee,
		BusinessUnit: in.BusinessUnit, Status: in.Status, Priority: in.Priority,
		DueAt: in.DueAt, ExternalTicketID: in.ExternalTicketID, CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	}
	return id, nil
}

func (f *fakeRepo) GetByID(_ context.Context, projectID, id uint64) (*Ticket, error) {
	t := f.tickets[id]
	if t == nil || t.ProjectID != projectID {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (f *fakeRepo) List(_ context.Context, projectID uint64, limit, offset int32) ([]*Ticket, error) {
	out := []*Ticket{}
	for _, t := range f.tickets {
		if t.ProjectID == projectID {
			cp := *t
			out = append(out, &cp)
		}
	}
	if offset >= int32(len(out)) {
		return nil, nil
	}
	end := offset + limit
	if end > int32(len(out)) {
		end = int32(len(out))
	}
	return out[offset:end], nil
}

func (f *fakeRepo) Count(_ context.Context, projectID uint64) (int64, error) {
	var n int64
	for _, t := range f.tickets {
		if t.ProjectID == projectID {
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) LinkRisk(_ context.Context, in LinkRiskParams) error {
	link := &TicketRisk{
		ID: f.nextLinkID, TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		TicketID: in.TicketID, RiskID: in.RiskID, CreatedBy: in.ActorID,
	}
	f.nextLinkID++
	f.links[in.TicketID] = append(f.links[in.TicketID], link)
	return nil
}

func (f *fakeRepo) ListRisks(_ context.Context, projectID, ticketID uint64) ([]*TicketRisk, error) {
	out := []*TicketRisk{}
	for _, link := range f.links[ticketID] {
		if link.ProjectID == projectID {
			cp := *link
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeRepo) UpdateStatus(_ context.Context, in StatusUpdateParams) error {
	t := f.tickets[in.TicketID]
	if t == nil || t.ProjectID != in.ProjectID || t.Status != in.OldStatus {
		return ErrNotFound
	}
	t.Status = in.NewStatus
	t.Assignee = in.Assignee
	t.DueAt = in.DueAt
	t.Resolution = in.Resolution
	t.RetestResult = in.RetestResult
	t.ClosedAt = in.ClosedAt
	t.UpdatedBy = in.ActorID
	return nil
}

type fakeRiskService struct {
	risks           map[uint64]*risk.Risk
	transitions     []risk.StatusTransitionInput
	resolutionHours map[string]uint32
}

func newFakeRiskService() *fakeRiskService {
	return &fakeRiskService{risks: map[uint64]*risk.Risk{}, resolutionHours: map[string]uint32{}}
}

func (f *fakeRiskService) GetByID(_ context.Context, projectID, id uint64) (*risk.Risk, error) {
	r := f.risks[id]
	if r == nil || r.ProjectID != projectID {
		return nil, risk.ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeRiskService) TransitionStatus(_ context.Context, in risk.StatusTransitionInput) (*risk.Risk, error) {
	r := f.risks[in.RiskID]
	if r == nil || r.ProjectID != in.ProjectID {
		return nil, risk.ErrNotFound
	}
	f.transitions = append(f.transitions, in)
	switch in.Action {
	case risk.StatusActionConfirm:
		if r.Status != risk.StatusNew && r.Status != risk.StatusReopened {
			return nil, risk.ErrInvalidStatusTransition
		}
		r.Status = risk.StatusConfirmed
	case risk.StatusActionAssign:
		if r.Status != risk.StatusConfirmed && r.Status != risk.StatusReopened {
			return nil, risk.ErrInvalidStatusTransition
		}
		r.Status = risk.StatusAssigned
		r.Owner = in.Owner
		r.SLADueAt = in.SLADueAt
	case risk.StatusActionStartFix:
		if r.Status != risk.StatusAssigned {
			return nil, risk.ErrInvalidStatusTransition
		}
		r.Status = risk.StatusFixing
	case risk.StatusActionMarkFixed:
		if r.Status != risk.StatusFixing && r.Status != risk.StatusAssigned {
			return nil, risk.ErrInvalidStatusTransition
		}
		r.Status = risk.StatusFixed
	case risk.StatusActionAccept:
		if r.Status != risk.StatusConfirmed && r.Status != risk.StatusAssigned && r.Status != risk.StatusFixing {
			return nil, risk.ErrInvalidStatusTransition
		}
		r.Status = risk.StatusRiskAccepted
	case risk.StatusActionFalsePositive:
		if r.Status != risk.StatusNew && r.Status != risk.StatusConfirmed && r.Status != risk.StatusAssigned && r.Status != risk.StatusFixing {
			return nil, risk.ErrInvalidStatusTransition
		}
		r.Status = risk.StatusFalsePositive
	}
	cp := *r
	return &cp, nil
}

func (f *fakeRiskService) ResolveDueAt(_ context.Context, _ uint64, severity, businessUnit string, from time.Time) (time.Time, error) {
	hours := f.resolutionHours[severity+":"+businessUnit]
	if hours == 0 {
		hours = f.resolutionHours[severity+":"]
	}
	if hours == 0 {
		return time.Time{}, risk.ErrNotFound
	}
	return from.Add(time.Duration(hours) * time.Hour), nil
}

func TestCreateLinksMultipleRisksAndAssignsThem(t *testing.T) {
	repo := newFakeRepo()
	risks := newFakeRiskService()
	audits := &fakeAudit{}
	risks.risks[10] = &risk.Risk{ID: 10, ProjectID: 1, Status: risk.StatusNew}
	risks.risks[11] = &risk.Risk{ID: 11, ProjectID: 1, Status: risk.StatusConfirmed}
	svc := NewService(repo, WithRiskService(risks), WithAuditSink(audits))
	due := time.Now().UTC().Add(72 * time.Hour)

	ticket, err := svc.Create(context.Background(), CreateInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Title: "Patch exposed RDP",
		Assignee: "dev1", Priority: PriorityHigh, DueAt: due, RiskIDs: []uint64{10, 11}, ActorID: "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, StatusOpen, ticket.Status)
	assert.Equal(t, "dev1", ticket.Assignee)
	require.Len(t, repo.links[ticket.ID], 2)
	assert.Equal(t, risk.StatusAssigned, risks.risks[10].Status)
	assert.Equal(t, risk.StatusAssigned, risks.risks[11].Status)
	assert.Equal(t, "dev1", risks.risks[10].Owner)
	assert.Len(t, risks.transitions, 3, "new risk is confirmed then assigned; confirmed risk is assigned")
	require.Len(t, audits.events, 1)
	assert.Equal(t, ActionTicketCreate, audits.events[0].Action)
	assert.Equal(t, ResourceTypeTicket, audits.events[0].ResourceType)
	assert.Equal(t, "alice", audits.events[0].ActorID)
}

func TestCreateDerivesDueAtFromLinkedRiskSLA(t *testing.T) {
	repo := newFakeRepo()
	risks := newFakeRiskService()
	firstSeen := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	risks.risks[10] = &risk.Risk{ID: 10, ProjectID: 1, Status: risk.StatusConfirmed, Severity: risk.SeverityHigh, FirstSeen: firstSeen}
	risks.resolutionHours[risk.SeverityHigh+":"] = 24
	svc := NewService(repo, WithRiskService(risks))

	ticket, err := svc.Create(context.Background(), CreateInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Title: "Patch",
		Assignee: "dev1", RiskIDs: []uint64{10}, ActorID: "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, firstSeen.Add(24*time.Hour), ticket.DueAt)
}

func TestTicketStatusTransitionsDriveRiskFixingAndFixed(t *testing.T) {
	repo := newFakeRepo()
	risks := newFakeRiskService()
	audits := &fakeAudit{}
	risks.risks[10] = &risk.Risk{ID: 10, ProjectID: 1, Status: risk.StatusConfirmed}
	svc := NewService(repo, WithRiskService(risks), WithAuditSink(audits))
	due := time.Now().UTC().Add(24 * time.Hour)
	ticket, err := svc.Create(context.Background(), CreateInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Title: "Fix Jenkins",
		Assignee: "dev1", DueAt: due, RiskIDs: []uint64{10}, ActorID: "alice",
	})
	require.NoError(t, err)
	_, err = svc.Transition(context.Background(), TransitionInput{
		ProjectID: 1, TicketID: ticket.ID, Action: ActionAssign, ActorID: "alice", Assignee: "dev1", DueAt: due,
	})
	require.NoError(t, err)

	ticket, err = svc.Transition(context.Background(), TransitionInput{ProjectID: 1, TicketID: ticket.ID, Action: ActionStart, ActorID: "dev1"})
	require.NoError(t, err)
	assert.Equal(t, StatusInProgress, ticket.Status)
	assert.Equal(t, risk.StatusFixing, risks.risks[10].Status)

	ticket, err = svc.Transition(context.Background(), TransitionInput{ProjectID: 1, TicketID: ticket.ID, Action: ActionSubmitRetest, ActorID: "dev1"})
	require.NoError(t, err)
	assert.Equal(t, StatusPendingRetest, ticket.Status)

	ticket, err = svc.Transition(context.Background(), TransitionInput{
		ProjectID: 1, TicketID: ticket.ID, Action: ActionRetestPass, ActorID: "sec", Resolution: "patched",
	})
	require.NoError(t, err)
	assert.Equal(t, StatusClosed, ticket.Status)
	assert.Equal(t, risk.StatusFixed, risks.risks[10].Status)
	require.Len(t, audits.events, 5)
	assert.Equal(t, ActionTicketStatusChange, audits.events[len(audits.events)-1].Action)
	assert.Equal(t, "sec", audits.events[len(audits.events)-1].ActorID)
}

func TestRetestRejectKeepsRiskFixingAndRejectsTicket(t *testing.T) {
	repo := newFakeRepo()
	risks := newFakeRiskService()
	risks.risks[10] = &risk.Risk{ID: 10, ProjectID: 1, Status: risk.StatusConfirmed}
	svc := NewService(repo, WithRiskService(risks))
	due := time.Now().UTC().Add(24 * time.Hour)
	ticket, err := svc.Create(context.Background(), CreateInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Title: "Fix Jenkins",
		Assignee: "dev1", DueAt: due, RiskIDs: []uint64{10}, ActorID: "alice",
	})
	require.NoError(t, err)
	_, err = svc.Transition(context.Background(), TransitionInput{
		ProjectID: 1, TicketID: ticket.ID, Action: ActionAssign, ActorID: "alice", Assignee: "dev1", DueAt: due,
	})
	require.NoError(t, err)
	_, err = svc.Transition(context.Background(), TransitionInput{ProjectID: 1, TicketID: ticket.ID, Action: ActionStart, ActorID: "dev1"})
	require.NoError(t, err)
	_, err = svc.Transition(context.Background(), TransitionInput{ProjectID: 1, TicketID: ticket.ID, Action: ActionSubmitRetest, ActorID: "dev1"})
	require.NoError(t, err)

	ticket, err = svc.Transition(context.Background(), TransitionInput{
		ProjectID: 1, TicketID: ticket.ID, Action: ActionRetestReject, ActorID: "sec", RetestResult: "still exposed",
	})
	require.NoError(t, err)
	assert.Equal(t, StatusRejected, ticket.Status)
	assert.Equal(t, risk.StatusFixing, risks.risks[10].Status)
}

func TestRetestAcceptRiskCancelsTicketAndAcceptsRisk(t *testing.T) {
	repo := newFakeRepo()
	risks := newFakeRiskService()
	risks.risks[10] = &risk.Risk{ID: 10, ProjectID: 1, Status: risk.StatusConfirmed}
	svc := NewService(repo, WithRiskService(risks))
	ticket := moveTicketToPendingRetest(t, svc)
	expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)

	ticket, err := svc.Transition(context.Background(), TransitionInput{
		ProjectID: 1, TicketID: ticket.ID, Action: ActionAcceptRisk, ActorID: "sec",
		Reason: "compensating control", ApprovedBy: "ciso", ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	assert.Equal(t, StatusCancelled, ticket.Status)
	assert.Equal(t, risk.StatusRiskAccepted, risks.risks[10].Status)
	require.NotEmpty(t, risks.transitions)
	last := risks.transitions[len(risks.transitions)-1]
	assert.Equal(t, risk.StatusActionAccept, last.Action)
	assert.Equal(t, "ciso", last.ApprovedBy)
	assert.Equal(t, expiresAt, last.ExpiresAt)
}

func TestRetestFalsePositiveCancelsTicketAndMarksRisk(t *testing.T) {
	repo := newFakeRepo()
	risks := newFakeRiskService()
	risks.risks[10] = &risk.Risk{ID: 10, ProjectID: 1, Status: risk.StatusConfirmed}
	svc := NewService(repo, WithRiskService(risks))
	ticket := moveTicketToPendingRetest(t, svc)
	reviewAt := time.Now().UTC().Add(14 * 24 * time.Hour)

	ticket, err := svc.Transition(context.Background(), TransitionInput{
		ProjectID: 1, TicketID: ticket.ID, Action: ActionFalsePositive, ActorID: "sec",
		Reason: "scanner banner mismatch", ApprovedBy: "lead", ReviewRequiredAt: reviewAt,
	})
	require.NoError(t, err)
	assert.Equal(t, StatusCancelled, ticket.Status)
	assert.Equal(t, risk.StatusFalsePositive, risks.risks[10].Status)
}

func TestTicketRejectsInvalidTransition(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	due := time.Now().UTC().Add(24 * time.Hour)
	ticket, err := svc.Create(context.Background(), CreateInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Title: "Fix",
		Assignee: "dev1", DueAt: due, RiskIDs: []uint64{10}, ActorID: "alice",
	})
	require.NoError(t, err)

	_, err = svc.Transition(context.Background(), TransitionInput{ProjectID: 1, TicketID: ticket.ID, Action: ActionSubmitRetest, ActorID: "dev1"})
	require.ErrorIs(t, err, ErrInvalidTransition)
}

func TestCreateRejectsDuplicateRiskIDs(t *testing.T) {
	_, err := NewService(newFakeRepo()).Create(context.Background(), CreateInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Title: "Fix",
		Assignee: "dev1", DueAt: time.Now().UTC(), RiskIDs: []uint64{10, 10}, ActorID: "alice",
	})
	require.ErrorIs(t, err, ErrInvalidRiskID)
}

func moveTicketToPendingRetest(t *testing.T, svc *Service) *Ticket {
	t.Helper()
	due := time.Now().UTC().Add(24 * time.Hour)
	ticket, err := svc.Create(context.Background(), CreateInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Title: "Fix Jenkins",
		Assignee: "dev1", DueAt: due, RiskIDs: []uint64{10}, ActorID: "alice",
	})
	require.NoError(t, err)
	_, err = svc.Transition(context.Background(), TransitionInput{
		ProjectID: 1, TicketID: ticket.ID, Action: ActionAssign, ActorID: "alice", Assignee: "dev1", DueAt: due,
	})
	require.NoError(t, err)
	_, err = svc.Transition(context.Background(), TransitionInput{ProjectID: 1, TicketID: ticket.ID, Action: ActionStart, ActorID: "dev1"})
	require.NoError(t, err)
	ticket, err = svc.Transition(context.Background(), TransitionInput{ProjectID: 1, TicketID: ticket.ID, Action: ActionSubmitRetest, ActorID: "dev1"})
	require.NoError(t, err)
	return ticket
}
