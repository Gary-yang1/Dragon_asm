package project

import (
	"context"
	"database/sql"
	"errors"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// ErrNotFound is returned when no live (non-soft-deleted) project or member row
// matches the query.
var ErrNotFound = errors.New("project: not found")

// Repository is the storage interface the project service depends on. Tests
// inject a fake; production wires the sqlc-backed implementation.
//
// All implementations MUST exclude soft-deleted rows by default.
type Repository interface {
	GetByID(ctx context.Context, id uint64) (*Project, error)
	GetByCode(ctx context.Context, tenantID, code string) (*Project, error)
	// IsMember reports whether userID is an active member of projectID.
	IsMember(ctx context.Context, projectID uint64, userID string) (bool, error)
	// MemberRole returns the role of userID in projectID, or ErrNotFound when the
	// user is not a member of the live project.
	MemberRole(ctx context.Context, projectID uint64, userID string) (string, error)
}

// sqlcRepository implements Repository over dbgen queries. The underlying sqlc
// SQL filters on the soft-delete sentinel, so soft-deleted rows are excluded by
// default here.
type sqlcRepository struct {
	q *dbgen.Queries
}

// NewRepository wraps a dbgen.Queries (which holds any dbgen.DBTX, e.g. a
// *sql.DB or a sqlmock-backed DB in tests).
func NewRepository(q *dbgen.Queries) *sqlcRepository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) GetByID(ctx context.Context, id uint64) (*Project, error) {
	p, err := r.q.GetProjectByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomain(p), nil
}

func (r *sqlcRepository) GetByCode(ctx context.Context, tenantID, code string) (*Project, error) {
	p, err := r.q.GetProjectByCode(ctx, dbgen.GetProjectByCodeParams{
		TenantID:    tenantID,
		ProjectCode: code,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomain(p), nil
}

func (r *sqlcRepository) IsMember(ctx context.Context, projectID uint64, userID string) (bool, error) {
	_, err := r.q.GetProjectMemberRole(ctx, dbgen.GetProjectMemberRoleParams{
		ProjectID: projectID,
		UserID:    userID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, mapErr(err)
	}
	return true, nil
}

func (r *sqlcRepository) MemberRole(ctx context.Context, projectID uint64, userID string) (string, error) {
	role, err := r.q.GetProjectMemberRole(ctx, dbgen.GetProjectMemberRoleParams{
		ProjectID: projectID,
		UserID:    userID,
	})
	if err != nil {
		return "", mapErr(err)
	}
	return role, nil
}

// mapErr converts database/sql's no-rows sentinel into the domain ErrNotFound.
func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func toDomain(p dbgen.Project) *Project {
	desc := ""
	if p.Description.Valid {
		desc = p.Description.String
	}
	return &Project{
		ID:           p.ID,
		TenantID:     p.TenantID,
		OrgID:        p.OrgID,
		ProjectCode:  p.ProjectCode,
		Name:         p.Name,
		Owner:        p.Owner,
		BusinessUnit: p.BusinessUnit,
		Criticality:  p.Criticality,
		Status:       p.Status,
		Description:  desc,
		CreatedAt:    p.CreatedAt,
		UpdatedAt:    p.UpdatedAt,
		CreatedBy:    p.CreatedBy,
		UpdatedBy:    p.UpdatedBy,
	}
}
