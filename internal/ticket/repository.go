//revive:disable:exported

package ticket

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var ErrNotFound = errors.New("ticket: not found")

type Repository interface {
	Create(ctx context.Context, in CreateParams) (uint64, error)
	GetByID(ctx context.Context, projectID, id uint64) (*Ticket, error)
	List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Ticket, error)
	Count(ctx context.Context, projectID uint64) (int64, error)
	LinkRisk(ctx context.Context, in LinkRiskParams) error
	ListRisks(ctx context.Context, projectID, ticketID uint64) ([]*TicketRisk, error)
	UpdateStatus(ctx context.Context, in StatusUpdateParams) error
}

type CreateParams struct {
	TenantID         string
	OrgID            string
	ProjectID        uint64
	Title            string
	Description      string
	Assignee         string
	BusinessUnit     string
	Status           string
	Priority         string
	DueAt            time.Time
	ExternalTicketID string
	ActorID          string
}

type LinkRiskParams struct {
	TenantID  string
	OrgID     string
	ProjectID uint64
	TicketID  uint64
	RiskID    uint64
	ActorID   string
}

type StatusUpdateParams struct {
	ProjectID    uint64
	TicketID     uint64
	OldStatus    string
	NewStatus    string
	Assignee     string
	DueAt        time.Time
	Resolution   string
	RetestResult string
	ClosedAt     time.Time
	ActorID      string
}

type sqlcRepository struct {
	q *dbgen.Queries
}

func NewRepository(q *dbgen.Queries) Repository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) Create(ctx context.Context, in CreateParams) (uint64, error) {
	res, err := r.q.CreateTicket(ctx, dbgen.CreateTicketParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		Title: in.Title, Description: in.Description, Assignee: in.Assignee,
		BusinessUnit: in.BusinessUnit, Status: in.Status, Priority: in.Priority,
		DueAt: timeForDB(in.DueAt), ExternalTicketID: in.ExternalTicketID,
		CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetByID(ctx context.Context, projectID, id uint64) (*Ticket, error) {
	row, err := r.q.GetTicketByID(ctx, dbgen.GetTicketByIDParams{ID: id, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toTicket(row), nil
}

func (r *sqlcRepository) List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Ticket, error) {
	rows, err := r.q.ListTicketsByProject(ctx, dbgen.ListTicketsByProjectParams{ProjectID: projectID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, err
	}
	out := make([]*Ticket, 0, len(rows))
	for _, row := range rows {
		out = append(out, toTicket(row))
	}
	return out, nil
}

func (r *sqlcRepository) Count(ctx context.Context, projectID uint64) (int64, error) {
	return r.q.CountTicketsByProject(ctx, projectID)
}

func (r *sqlcRepository) LinkRisk(ctx context.Context, in LinkRiskParams) error {
	_, err := r.q.LinkTicketRisk(ctx, dbgen.LinkTicketRiskParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		TicketID: in.TicketID, RiskID: in.RiskID, CreatedBy: in.ActorID,
	})
	return err
}

func (r *sqlcRepository) ListRisks(ctx context.Context, projectID, ticketID uint64) ([]*TicketRisk, error) {
	rows, err := r.q.ListTicketRisks(ctx, dbgen.ListTicketRisksParams{ProjectID: projectID, TicketID: ticketID})
	if err != nil {
		return nil, err
	}
	out := make([]*TicketRisk, 0, len(rows))
	for _, row := range rows {
		out = append(out, toTicketRisk(row))
	}
	return out, nil
}

func (r *sqlcRepository) UpdateStatus(ctx context.Context, in StatusUpdateParams) error {
	res, err := r.q.UpdateTicketStatus(ctx, dbgen.UpdateTicketStatusParams{
		Status: in.NewStatus, Assignee: in.Assignee, DueAt: timeForDB(in.DueAt),
		Resolution: in.Resolution, RetestResult: in.RetestResult, ClosedAt: timeForDB(in.ClosedAt),
		UpdatedBy: in.ActorID, ID: in.TicketID, ProjectID: in.ProjectID, Status_2: in.OldStatus,
	})
	return rowsAffectedErr(res, err)
}

func toTicket(row dbgen.Ticket) *Ticket {
	return &Ticket{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Title: row.Title, Description: row.Description, Assignee: row.Assignee,
		BusinessUnit: row.BusinessUnit, Status: row.Status, Priority: row.Priority,
		DueAt: row.DueAt, Resolution: row.Resolution, RetestResult: row.RetestResult,
		ExternalTicketID: row.ExternalTicketID, ClosedAt: row.ClosedAt,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, CreatedBy: row.CreatedBy, UpdatedBy: row.UpdatedBy,
	}
}

func toTicketRisk(row dbgen.TicketRisk) *TicketRisk {
	return &TicketRisk{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		TicketID: row.TicketID, RiskID: row.RiskID, CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
	}
}

func resultID(res sql.Result) (uint64, error) {
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id < 0 {
		return 0, fmt.Errorf("ticket: negative insert id %d", id)
	}
	return uint64(id), nil
}

func rowsAffectedErr(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func timeForDB(t time.Time) time.Time {
	if t.IsZero() {
		return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return t.UTC()
}

func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
