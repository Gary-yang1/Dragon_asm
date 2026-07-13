package asset

import (
	"context"
	"database/sql"
	"errors"
	"time"

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
	// Count returns the number of live assets in a project (for list pagination
	// totals). It uses the same project + soft-delete scoping as List.
	Count(ctx context.Context, projectID uint64) (int64, error)
	// Update mutates the non-key metadata fields of one project-scoped live asset.
	// The WHERE clause carries project_id so a cross-project update is impossible
	// at the DB layer. It returns ErrNotFound when no live row matched.
	Update(ctx context.Context, in UpdateParams) error
	// UpdateLifecycle applies a lifecycle transition (miss_count + status) to one
	// project-scoped live asset. The service computes the target after reading the
	// current row and the configurable threshold; the repo just applies it. The
	// WHERE clause carries project_id so a cross-project transition is impossible.
	UpdateLifecycle(ctx context.Context, in UpdateLifecycleParams) error
}

// RootDomainResolver is implemented by the sqlc repository after the project
// workspace migration. Import uses it opportunistically to link an imported
// subdomain to the longest matching project root-domain profile.
type RootDomainResolver interface {
	FindRootDomainAssetID(ctx context.Context, projectID uint64, subdomain string) (uint64, error)
}

// UpdateParams carries the operator-editable fields for Update. The identity
// fields (asset_type/asset_key/value) are deliberately absent: they are the
// normalized key and are never edited. Status is restricted to the live
// statuses by the service before this is populated.
type UpdateParams struct {
	ProjectID    uint64
	ID           uint64
	DisplayName  string
	Source       string
	Owner        string
	BusinessUnit string
	Status       string
	ActorID      string
}

// UpdateLifecycleParams carries a lifecycle transition. MissCount and Status are
// set together; ActorID records who/what drove the transition (the discovery
// pipeline, an operator, etc.).
type UpdateLifecycleParams struct {
	ProjectID uint64
	ID        uint64
	MissCount uint32
	Status    string
	ActorID   string
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
	ObservedAt   time.Time
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
	observedAt := in.ObservedAt
	if observedAt.IsZero() {
		observedAt = nowFn()
	}
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
		FirstSeen:    observedAt,
		LastSeen:     observedAt,
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

func (r *sqlcRepository) Count(ctx context.Context, projectID uint64) (int64, error) {
	n, err := r.q.CountAssetsByProject(ctx, projectID)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (r *sqlcRepository) FindRootDomainAssetID(ctx context.Context, projectID uint64, subdomain string) (uint64, error) {
	id, err := r.q.FindProjectRootDomainAsset(ctx, dbgen.FindProjectRootDomainAssetParams{
		ProjectID: projectID,
		Value:     subdomain,
	})
	if err != nil {
		return 0, mapErr(err)
	}
	return id, nil
}

// Update applies the editable fields. sqlc's :exec does not surface
// rows-affected, so the service re-reads via GetByID to confirm the update
// landed; a non-existent or soft-deleted asset is therefore surfaced as
// ErrNotFound from that re-read rather than as a silent no-op.
func (r *sqlcRepository) Update(ctx context.Context, in UpdateParams) error {
	return r.q.UpdateAssetFields(ctx, dbgen.UpdateAssetFieldsParams{
		DisplayName:  in.DisplayName,
		Source:       in.Source,
		Owner:        in.Owner,
		BusinessUnit: in.BusinessUnit,
		Status:       in.Status,
		UpdatedBy:    in.ActorID,
		ID:           in.ID,
		ProjectID:    in.ProjectID,
	})
}

// UpdateLifecycle applies the (miss_count, status) transition. Like Update, the
// service re-reads via GetByID to confirm and to surface a non-existent /
// cross-project / soft-deleted asset as ErrNotFound.
func (r *sqlcRepository) UpdateLifecycle(ctx context.Context, in UpdateLifecycleParams) error {
	return r.q.UpdateAssetLifecycle(ctx, dbgen.UpdateAssetLifecycleParams{
		MissCount: in.MissCount,
		Status:    in.Status,
		UpdatedBy: in.ActorID,
		ID:        in.ID,
		ProjectID: in.ProjectID,
	})
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
		MissCount:    a.MissCount,
		Status:       a.Status,
		FirstSeen:    a.FirstSeen,
		LastSeen:     a.LastSeen,
		CreatedAt:    a.CreatedAt,
		UpdatedAt:    a.UpdatedAt,
		CreatedBy:    a.CreatedBy,
		UpdatedBy:    a.UpdatedBy,
	}
}
