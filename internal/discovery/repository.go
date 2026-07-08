package discovery

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var ErrNotFound = errors.New("discovery: scope not found")

type Repository interface {
	CreateScope(ctx context.Context, in CreateScopeParams) (uint64, error)
	GetScope(ctx context.Context, projectID, scopeID uint64) (*Scope, error)
	ListScopes(ctx context.Context, projectID uint64) ([]*Scope, error)
	UpdateScope(ctx context.Context, in UpdateScopeParams) error
	DeactivateScope(ctx context.Context, projectID, scopeID uint64, actorID string, updatedAtNow func() time.Time) error

	InsertScopeTarget(ctx context.Context, in InsertScopeTargetParams) error
	ListScopeTargets(ctx context.Context, projectID, scopeID uint64) ([]*ScopeTarget, error)
	ClearScopeTargets(ctx context.Context, projectID, scopeID uint64, actorID string, deletedAt time.Time) error
}

type CreateScopeParams struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	Name         string
	Status       string
	AuthorizedBy string
	ValidFrom    time.Time
	ValidUntil   time.Time
	ActorID      string
}

type UpdateScopeParams struct {
	ScopeID      uint64
	TenantID     string
	OrgID        string
	ProjectID    uint64
	Name         string
	Status       string
	AuthorizedBy string
	ValidFrom    time.Time
	ValidUntil   time.Time
	ActorID      string
}

type InsertScopeTargetParams struct {
	TenantID   string
	OrgID      string
	ProjectID  uint64
	ScopeID    uint64
	TargetType string
	MatchMode  string
	Value      string
	ActorID    string
}

type sqlcRepository struct {
	q *dbgen.Queries
}

func NewRepository(q *dbgen.Queries) Repository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) CreateScope(ctx context.Context, in CreateScopeParams) (uint64, error) {
	res, err := r.q.CreateScope(ctx, dbgen.CreateScopeParams{
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
	})
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return uint64(id), nil
}

func (r *sqlcRepository) GetScope(ctx context.Context, projectID, scopeID uint64) (*Scope, error) {
	row, err := r.q.GetScopeByID(ctx, dbgen.GetScopeByIDParams{
		ID:        scopeID,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomainScope(row), nil
}

func (r *sqlcRepository) ListScopes(ctx context.Context, projectID uint64) ([]*Scope, error) {
	rows, err := r.q.ListScopesByProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*Scope, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomainScope(row))
	}
	return out, nil
}

func (r *sqlcRepository) UpdateScope(ctx context.Context, in UpdateScopeParams) error {
	return r.q.UpdateScope(ctx, dbgen.UpdateScopeParams{
		Name:         in.Name,
		Status:       in.Status,
		AuthorizedBy: in.AuthorizedBy,
		ValidFrom:    in.ValidFrom,
		ValidUntil:   in.ValidUntil,
		UpdatedBy:    in.ActorID,
		ID:           in.ScopeID,
		ProjectID:    in.ProjectID,
	})
}

func (r *sqlcRepository) DeactivateScope(ctx context.Context, projectID, scopeID uint64, actorID string, updatedAtNow func() time.Time) error {
	if updatedAtNow == nil {
		updatedAtNow = time.Now
	}
	return r.q.UpdateScopeStatus(ctx, dbgen.UpdateScopeStatusParams{
		Status:    StatusInactive,
		UpdatedBy: actorID,
		UpdatedAt: updatedAtNow().UTC(),
		ID:        scopeID,
		ProjectID: projectID,
	})
}

func (r *sqlcRepository) InsertScopeTarget(ctx context.Context, in InsertScopeTargetParams) error {
	return r.q.InsertScopeTarget(ctx, dbgen.InsertScopeTargetParams{
		TenantID:    in.TenantID,
		OrgID:       in.OrgID,
		ProjectID:   in.ProjectID,
		ScopeID:     in.ScopeID,
		TargetType:  in.TargetType,
		MatchMode:   in.MatchMode,
		TargetValue: in.Value,
		CreatedBy:   in.ActorID,
		UpdatedBy:   in.ActorID,
	})
}

func (r *sqlcRepository) ListScopeTargets(ctx context.Context, projectID, scopeID uint64) ([]*ScopeTarget, error) {
	rows, err := r.q.ListScopeTargetsByScope(ctx, dbgen.ListScopeTargetsByScopeParams{
		ScopeID:   scopeID,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*ScopeTarget, 0, len(rows))
	for _, row := range rows {
		out = append(out, &ScopeTarget{
			ID:         row.ID,
			TenantID:   row.TenantID,
			OrgID:      row.OrgID,
			ProjectID:  row.ProjectID,
			ScopeID:    row.ScopeID,
			TargetType: row.TargetType,
			MatchMode:  row.MatchMode,
			Value:      row.TargetValue,
			CreatedAt:  row.CreatedAt,
			UpdatedAt:  row.UpdatedAt,
			CreatedBy:  row.CreatedBy,
			UpdatedBy:  row.UpdatedBy,
			DeletedAt:  row.DeletedAt,
		})
	}
	return out, nil
}

func (r *sqlcRepository) ClearScopeTargets(ctx context.Context, projectID, scopeID uint64, actorID string, deletedAt time.Time) error {
	return r.q.SoftDeleteScopeTargets(ctx, dbgen.SoftDeleteScopeTargetsParams{
		DeletedAt: deletedAt.UTC(),
		UpdatedBy: actorID,
		ScopeID:   scopeID,
		ProjectID: projectID,
	})
}

func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func toDomainScope(row dbgen.Scope) *Scope {
	return &Scope{
		ID:           row.ID,
		TenantID:     row.TenantID,
		OrgID:        row.OrgID,
		ProjectID:    row.ProjectID,
		Name:         row.Name,
		Status:       row.Status,
		AuthorizedBy: row.AuthorizedBy,
		ValidFrom:    row.ValidFrom,
		ValidUntil:   row.ValidUntil,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
		CreatedBy:    row.CreatedBy,
		UpdatedBy:    row.UpdatedBy,
		DeletedAt:    row.DeletedAt,
	}
}
