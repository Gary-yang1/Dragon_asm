package asset_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
)

// fakeRelationRepo is an in-memory RelationRepository keyed by
// "<projectID>:<from>:<to>:<type>". It mirrors the SQL ON DUPLICATE KEY UPDATE
// (refresh source/confidence/updated_by, preserve the rest) so tests can assert
// idempotency and bidirectional listing without a DB.
type fakeRelationRepo struct {
	rows   map[string]*asset.Relation
	nextID uint64
}

func newFakeRelationRepo() *fakeRelationRepo {
	return &fakeRelationRepo{rows: map[string]*asset.Relation{}}
}

func relKey(projectID, from, to uint64, relType string) string {
	return fmt.Sprintf("%d:%d:%d:%s", projectID, from, to, relType)
}

func (f *fakeRelationRepo) Upsert(_ context.Context, in asset.UpsertRelationParams) error {
	k := relKey(in.ProjectID, in.FromAssetID, in.ToAssetID, in.RelationType)
	if ex, ok := f.rows[k]; ok {
		ex.Source = in.Source
		ex.Confidence = in.Confidence
		ex.UpdatedBy = in.ActorID
		return nil
	}
	f.nextID++
	f.rows[k] = &asset.Relation{
		ID:           f.nextID,
		TenantID:     in.TenantID,
		OrgID:        in.OrgID,
		ProjectID:    in.ProjectID,
		FromAssetID:  in.FromAssetID,
		ToAssetID:    in.ToAssetID,
		RelationType: in.RelationType,
		Source:       in.Source,
		Confidence:   in.Confidence,
		CreatedBy:    in.ActorID,
		UpdatedBy:    in.ActorID,
	}
	return nil
}

func (f *fakeRelationRepo) GetByEndpoints(_ context.Context, projectID, from, to uint64, relType string) (*asset.Relation, error) {
	if r, ok := f.rows[relKey(projectID, from, to, relType)]; ok {
		return r, nil
	}
	return nil, asset.ErrNotFound
}

func (f *fakeRelationRepo) ListByAsset(_ context.Context, projectID, assetID uint64, _, _ int32) ([]*asset.Relation, error) {
	var out []*asset.Relation
	for _, r := range f.rows {
		if r.ProjectID != projectID {
			continue
		}
		if r.FromAssetID != assetID && r.ToAssetID != assetID {
			continue
		}
		cp := *r
		if cp.FromAssetID == assetID {
			cp.Direction = asset.DirectionOut
		} else {
			cp.Direction = asset.DirectionIn
		}
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeRelationRepo) CountByAsset(_ context.Context, projectID, assetID uint64) (int64, error) {
	var n int64
	for _, r := range f.rows {
		if r.ProjectID == projectID && (r.FromAssetID == assetID || r.ToAssetID == assetID) {
			n++
		}
	}
	return n, nil
}

// newRelationService builds a Service over an in-memory asset repo + relation
// repo (non-tx path, no audit) for relation service tests.
func newRelationService(t *testing.T) (*asset.Service, *fakeRepo, *fakeRelationRepo) {
	t.Helper()
	repo := newFakeRepo()
	relRepo := newFakeRelationRepo()
	svc := asset.NewService(repo, asset.WithRelationRepository(relRepo))
	return svc, repo, relRepo
}

// Acceptance: a relation whose to-asset lives in another project is rejected —
// the service validates both endpoints exist in the relation's project.
func TestUpsertRelationRejectsCrossProject(t *testing.T) {
	svc, _, _ := newRelationService(t)
	ctx := context.Background()

	a, err := svc.Import(ctx, asset.ImportInput{ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "from.com"})
	require.NoError(t, err)
	c, err := svc.Import(ctx, asset.ImportInput{ProjectID: 2, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "to.com"})
	require.NoError(t, err)

	_, err = svc.UpsertRelation(ctx, asset.RelationInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1",
		FromAssetID: a.ID, ToAssetID: c.ID, RelationType: asset.RelationResolvesTo,
	}, asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrRelationEndpointNotFound, "to-asset in another project is rejected")
}

// Acceptance: re-upserting the same (from, to, type) edge is idempotent — one
// row, mutable fields refreshed.
func TestUpsertRelationIdempotent(t *testing.T) {
	svc, _, relRepo := newRelationService(t)
	ctx := context.Background()

	a, err := svc.Import(ctx, asset.ImportInput{ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "a.com"})
	require.NoError(t, err)
	b, err := svc.Import(ctx, asset.ImportInput{ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeIP, Value: "1.2.3.4"})
	require.NoError(t, err)

	in := asset.RelationInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1",
		FromAssetID: a.ID, ToAssetID: b.ID, RelationType: asset.RelationResolvesTo,
		Source: "seed", Confidence: 50,
	}
	r1, err := svc.UpsertRelation(ctx, in, asset.AuditMeta{})
	require.NoError(t, err)

	in.Source = "scan"
	in.Confidence = 90
	r2, err := svc.UpsertRelation(ctx, in, asset.AuditMeta{})
	require.NoError(t, err)

	assert.Equal(t, r1.ID, r2.ID, "re-upsert must not create a new edge")
	assert.Len(t, relRepo.rows, 1)
	assert.Equal(t, "scan", r2.Source)
	assert.Equal(t, uint8(90), r2.Confidence)
}

// Acceptance: listing an asset's relations returns out-edges for the source and
// in-edges for the target (bidirectional query).
func TestListRelationsBidirectional(t *testing.T) {
	svc, _, _ := newRelationService(t)
	ctx := context.Background()

	a, err := svc.Import(ctx, asset.ImportInput{ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "a.com"})
	require.NoError(t, err)
	b, err := svc.Import(ctx, asset.ImportInput{ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeIP, Value: "1.2.3.4"})
	require.NoError(t, err)
	_, err = svc.UpsertRelation(ctx, asset.RelationInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1",
		FromAssetID: a.ID, ToAssetID: b.ID, RelationType: asset.RelationResolvesTo,
	}, asset.AuditMeta{})
	require.NoError(t, err)

	out, total, err := svc.ListRelations(ctx, 1, a.ID, 50, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, out, 1)
	assert.Equal(t, asset.DirectionOut, out[0].Direction, "source sees an out-edge")
	assert.Equal(t, b.ID, out[0].ToAssetID)

	in, total, err := svc.ListRelations(ctx, 1, b.ID, 50, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, in, 1)
	assert.Equal(t, asset.DirectionIn, in[0].Direction, "target sees an in-edge")
	assert.Equal(t, a.ID, in[0].FromAssetID)

	// A project-scoped list rejects a parent that does not exist in that project:
	// querying project 2 for project 1's asset is ErrNotFound, not an empty 200
	// (no cross-project leak).
	_, _, err = svc.ListRelations(ctx, 2, a.ID, 50, 0)
	require.ErrorIs(t, err, asset.ErrNotFound, "cross-project parent is not found")
}

// Self-loops and bad relation types are rejected before any write.
func TestUpsertRelationValidation(t *testing.T) {
	svc, _, relRepo := newRelationService(t)
	ctx := context.Background()

	a, err := svc.Import(ctx, asset.ImportInput{ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "a.com"})
	require.NoError(t, err)

	_, err = svc.UpsertRelation(ctx, asset.RelationInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1",
		FromAssetID: a.ID, ToAssetID: a.ID, RelationType: asset.RelationContains,
	}, asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrSelfRelation)

	_, err = svc.UpsertRelation(ctx, asset.RelationInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1",
		FromAssetID: a.ID, ToAssetID: 999, RelationType: "bogus",
	}, asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrInvalidRelationType)

	assert.Empty(t, relRepo.rows, "no edge written on validation failure")
}

// ListRelations rejects a nonexistent parent asset with ErrNotFound (not an empty
// 200), and a valid parent with no edges returns an empty list — the two cases
// are distinguishable.
func TestListRelationsParentExistence(t *testing.T) {
	svc, _, _ := newRelationService(t)
	ctx := context.Background()

	a, err := svc.Import(ctx, asset.ImportInput{ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "a.com"})
	require.NoError(t, err)

	// Nonexistent parent in the project -> ErrNotFound.
	_, _, err = svc.ListRelations(ctx, 1, 9999, 50, 0)
	require.ErrorIs(t, err, asset.ErrNotFound)

	// Cross-project parent (asset exists in project 2, queried in project 1) ->
	// ErrNotFound, not a leak of project 2's edges.
	b, err := svc.Import(ctx, asset.ImportInput{ProjectID: 2, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "b.com"})
	require.NoError(t, err)
	_, _, err = svc.ListRelations(ctx, 1, b.ID, 50, 0)
	require.ErrorIs(t, err, asset.ErrNotFound, "parent must exist in the queried project")

	// Valid parent with no edges -> empty list, no error.
	rows, total, err := svc.ListRelations(ctx, 1, a.ID, 50, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, rows)
}
