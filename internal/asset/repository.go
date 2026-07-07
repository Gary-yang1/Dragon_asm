package asset

import (
	"context"
	"database/sql"
	"errors"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// ErrNotFound is returned when no live (non-soft-deleted) asset matches a
// project-scoped lookup.
var ErrNotFound = errors.New("asset: not found")

// Repository is the storage interface the asset service depends on. Tests inject
// a fake; production wires the sqlc-backed implementation.
//
// Every method is project-scoped: project_id is a required argument, never an
// optional filter, so cross-project reads/writes are impossible by construction.
// All reads exclude soft-deleted rows by default.
type Repository interface {
	// Upsert inserts a new asset or, when (project_id, asset_key) already exists,
	// refreshes only the discovery-updatable fields. It is idempotent.
	Upsert(ctx context.Context, in UpsertParams) error
	GetByKey(ctx context.Context, projectID uint64, assetKey string) (*Asset, error)
	GetByID(ctx context.Context, projectID, id uint64) (*Asset, error)
	List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Asset, error)
}

// UpsertParams carries the already-normalized fields for an idempotent write.
// AssetType/AssetKey/Value are expected to come from Normalize.
type UpsertParams struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	AssetType    string
	AssetKey     string
	DisplayName  string
	Value        string
	Source       string
	Owner        string
	BusinessUnit string
	Confidence   uint8
	Status       string
	ActorID      string
}

type sqlcRepository struct {
	q *dbgen.Queries
}

// NewRepository wraps a dbgen.Queries (holding any dbgen.DBTX, e.g. *sql.DB or a
// sqlmock-backed DB in tests).
func NewRepository(q *dbgen.Queries) Repository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) Upsert(ctx context.Context, in UpsertParams) error {
	_, err := r.q.UpsertAsset(ctx, dbgen.UpsertAssetParams{
		TenantID:     in.TenantID,
		OrgID:        in.OrgID,
		ProjectID:    in.ProjectID,
		AssetType:    in.AssetType,
		AssetKey:     in.AssetKey,
		DisplayName:  in.DisplayName,
		Value:        in.Value,
		Source:       in.Source,
		Owner:        in.Owner,
		BusinessUnit: in.BusinessUnit,
		Confidence:   in.Confidence,
		Status:       in.Status,
		FirstSeen:    nowFn(),
		LastSeen:     nowFn(),
		CreatedBy:    in.ActorID,
		UpdatedBy:    in.ActorID,
	})
	return err
}

func (r *sqlcRepository) GetByKey(ctx context.Context, projectID uint64, assetKey string) (*Asset, error) {
	a, err := r.q.GetAssetByKey(ctx, dbgen.GetAssetByKeyParams{
		ProjectID: projectID,
		AssetKey:  assetKey,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomain(a), nil
}

func (r *sqlcRepository) GetByID(ctx context.Context, projectID, id uint64) (*Asset, error) {
	a, err := r.q.GetAssetByID(ctx, dbgen.GetAssetByIDParams{
		ID:        id,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomain(a), nil
}

func (r *sqlcRepository) List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Asset, error) {
	rows, err := r.q.ListAssetsByProject(ctx, dbgen.ListAssetsByProjectParams{
		ProjectID: projectID,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*Asset, 0, len(rows))
	for _, a := range rows {
		out = append(out, toDomain(a))
	}
	return out, nil
}

// mapErr converts database/sql's no-rows sentinel into the domain ErrNotFound.
func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func toDomain(a dbgen.Asset) *Asset {
	return &Asset{
		ID:           a.ID,
		TenantID:     a.TenantID,
		OrgID:        a.OrgID,
		ProjectID:    a.ProjectID,
		AssetType:    a.AssetType,
		AssetKey:     a.AssetKey,
		DisplayName:  a.DisplayName,
		Value:        a.Value,
		Source:       a.Source,
		Owner:        a.Owner,
		BusinessUnit: a.BusinessUnit,
		Confidence:   a.Confidence,
		Status:       a.Status,
		FirstSeen:    a.FirstSeen,
		LastSeen:     a.LastSeen,
		CreatedAt:    a.CreatedAt,
		UpdatedAt:    a.UpdatedAt,
		CreatedBy:    a.CreatedBy,
		UpdatedBy:    a.UpdatedBy,
	}
}
