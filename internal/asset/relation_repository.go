package asset

import (
	"context"
	"database/sql"
	"errors"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// RelationRepository is the storage interface for asset_relation rows. Tests
// inject a fake; production wires the sqlc-backed implementation. Every method
// is project-scoped and excludes soft-deleted rows by default.
type RelationRepository interface {
	// Upsert inserts a new edge or, when (project_id, from, to, type) already
	// exists, refreshes only the discovery-updatable fields. Idempotent.
	Upsert(ctx context.Context, in UpsertRelationParams) error
	// GetByEndpoints returns the live edge for (project, from, to, type), or
	// ErrNotFound when no live row matches.
	GetByEndpoints(ctx context.Context, projectID, fromID, toID uint64, relationType string) (*Relation, error)
	// ListByAsset returns live relations where the asset is either endpoint
	// (both directions), paginated.
	ListByAsset(ctx context.Context, projectID, assetID uint64, limit, offset int32) ([]*Relation, error)
	// CountByAsset returns the live relation count for the both-directions query.
	CountByAsset(ctx context.Context, projectID, assetID uint64) (int64, error)
}

// UpsertRelationParams carries the already-validated fields for an idempotent
// relation write. TenantID/OrgID/ProjectID scope the edge and must match both
// endpoints.
type UpsertRelationParams struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	FromAssetID  uint64
	ToAssetID    uint64
	RelationType string
	Source       string
	Confidence   uint8
	ActorID      string
}

type sqlcRelationRepository struct {
	q *dbgen.Queries
}

// NewRelationRepository wraps a dbgen.Queries for asset_relation access.
func NewRelationRepository(q *dbgen.Queries) RelationRepository {
	return &sqlcRelationRepository{q: q}
}

func (r *sqlcRelationRepository) Upsert(ctx context.Context, in UpsertRelationParams) error {
	_, err := r.q.UpsertRelation(ctx, dbgen.UpsertRelationParams{
		TenantID:     in.TenantID,
		OrgID:        in.OrgID,
		ProjectID:    in.ProjectID,
		FromAssetID:  in.FromAssetID,
		ToAssetID:    in.ToAssetID,
		RelationType: in.RelationType,
		Source:       in.Source,
		Confidence:   in.Confidence,
		FirstSeen:    nowFn(),
		LastSeen:     nowFn(),
		CreatedBy:    in.ActorID,
		UpdatedBy:    in.ActorID,
	})
	return err
}

func (r *sqlcRelationRepository) GetByEndpoints(ctx context.Context, projectID, fromID, toID uint64, relationType string) (*Relation, error) {
	row, err := r.q.GetRelationByEndpoints(ctx, dbgen.GetRelationByEndpointsParams{
		ProjectID:    projectID,
		FromAssetID:  fromID,
		ToAssetID:    toID,
		RelationType: relationType,
	})
	if err != nil {
		return nil, mapRelationErr(err)
	}
	return baseRelation(row), nil
}

func (r *sqlcRelationRepository) ListByAsset(ctx context.Context, projectID, assetID uint64, limit, offset int32) ([]*Relation, error) {
	rows, err := r.q.ListRelationsByAsset(ctx, dbgen.ListRelationsByAssetParams{
		ProjectID:   projectID,
		FromAssetID: assetID,
		ToAssetID:   assetID,
		Limit:       limit,
		Offset:      offset,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*Relation, 0, len(rows))
	for _, row := range rows {
		out = append(out, relationWithDirection(row, assetID))
	}
	return out, nil
}

func (r *sqlcRelationRepository) CountByAsset(ctx context.Context, projectID, assetID uint64) (int64, error) {
	n, err := r.q.CountRelationsByAsset(ctx, dbgen.CountRelationsByAssetParams{
		ProjectID:   projectID,
		FromAssetID: assetID,
		ToAssetID:   assetID,
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// baseRelation maps a sqlc row to the domain Relation without a direction tag
// (used by GetByEndpoints, where no queried-asset context exists).
func baseRelation(a dbgen.AssetRelation) *Relation {
	return &Relation{
		ID:           a.ID,
		TenantID:     a.TenantID,
		OrgID:        a.OrgID,
		ProjectID:    a.ProjectID,
		FromAssetID:  a.FromAssetID,
		ToAssetID:    a.ToAssetID,
		RelationType: a.RelationType,
		Source:       a.Source,
		Confidence:   a.Confidence,
		FirstSeen:    a.FirstSeen,
		LastSeen:     a.LastSeen,
		CreatedAt:    a.CreatedAt,
		UpdatedAt:    a.UpdatedAt,
		CreatedBy:    a.CreatedBy,
		UpdatedBy:    a.UpdatedBy,
	}
}

// relationWithDirection maps a sqlc row and tags Direction relative to the
// queried asset id ("out" if it is the source, else "in").
func relationWithDirection(a dbgen.AssetRelation, assetID uint64) *Relation {
	r := baseRelation(a)
	if a.FromAssetID == assetID {
		r.Direction = DirectionOut
	} else {
		r.Direction = DirectionIn
	}
	return r
}

// mapRelationErr converts database/sql's no-rows sentinel into the domain
// ErrNotFound so callers can surface a 404 for a missing edge.
func mapRelationErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
