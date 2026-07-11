package asset_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
)

// fakeRepo is an in-memory Repository keyed by "<projectID>:<assetKey>" so tests
// can assert both idempotency and project-level isolation without a DB.
type fakeRepo struct {
	rows               map[string]*asset.Asset
	rootDomainAssetIDs map[string]uint64
	nextID             uint64
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{rows: map[string]*asset.Asset{}, rootDomainAssetIDs: map[string]uint64{}}
}

func key(projectID uint64, assetKey string) string {
	return fmt.Sprintf("%d:%s", projectID, assetKey)
}

func (f *fakeRepo) Upsert(_ context.Context, in asset.UpsertParams) error {
	k := key(in.ProjectID, in.AssetKey)
	if existing, ok := f.rows[k]; ok {
		// Mirror the SQL ON DUPLICATE KEY UPDATE: refresh only mutable fields,
		// preserve first_seen/owner/business_unit/status.
		existing.Source = in.Source
		existing.Confidence = in.Confidence
		existing.DisplayName = in.DisplayName
		existing.Value = in.Value
		return nil
	}
	f.nextID++
	f.rows[k] = &asset.Asset{
		ID:           f.nextID,
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
	}
	return nil
}

func (f *fakeRepo) GetByKey(_ context.Context, projectID uint64, assetKey string) (*asset.Asset, error) {
	if a, ok := f.rows[key(projectID, assetKey)]; ok {
		return cloneAsset(a), nil
	}
	return nil, asset.ErrNotFound
}

func (f *fakeRepo) GetByID(_ context.Context, projectID, id uint64) (*asset.Asset, error) {
	for _, a := range f.rows {
		if a.ProjectID == projectID && a.ID == id {
			return cloneAsset(a), nil
		}
	}
	return nil, asset.ErrNotFound
}

func (f *fakeRepo) List(_ context.Context, projectID uint64, _, _ int32) ([]*asset.Asset, error) {
	var out []*asset.Asset
	for _, a := range f.rows {
		if a.ProjectID == projectID {
			out = append(out, cloneAsset(a))
		}
	}
	return out, nil
}

// cloneAsset returns a shallow copy so callers (and audit before/after snapshots)
// hold distinct values, matching the sqlc repository which builds a fresh struct
// per read. Without this, an in-place mutation by Update/UpdateLifecycle would
// retroactively change a previously returned "before" snapshot.
func cloneAsset(a *asset.Asset) *asset.Asset {
	cp := *a
	return &cp
}

func (f *fakeRepo) Count(_ context.Context, projectID uint64) (int64, error) {
	var n int64
	for _, a := range f.rows {
		if a.ProjectID == projectID {
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) Update(_ context.Context, in asset.UpdateParams) error {
	for _, a := range f.rows {
		if a.ProjectID == in.ProjectID && a.ID == in.ID {
			a.DisplayName = in.DisplayName
			a.Source = in.Source
			a.Owner = in.Owner
			a.BusinessUnit = in.BusinessUnit
			a.Status = in.Status
			a.UpdatedBy = in.ActorID
			return nil
		}
	}
	return asset.ErrNotFound
}

func (f *fakeRepo) UpdateLifecycle(_ context.Context, in asset.UpdateLifecycleParams) error {
	for _, a := range f.rows {
		if a.ProjectID == in.ProjectID && a.ID == in.ID {
			a.MissCount = in.MissCount
			a.Status = in.Status
			a.UpdatedBy = in.ActorID
			return nil
		}
	}
	return asset.ErrNotFound
}

func (f *fakeRepo) FindRootDomainAssetID(_ context.Context, projectID uint64, subdomain string) (uint64, error) {
	if id, ok := f.rootDomainAssetIDs[fmt.Sprintf("%d:%s", projectID, subdomain)]; ok {
		return id, nil
	}
	return 0, asset.ErrNotFound
}

// Acceptance: importing the same normalized asset twice in one project does not
// create a duplicate row; the second import refreshes mutable fields only.
func TestImportIdempotent(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	a1, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "Example.com", Source: "seed", Confidence: 50,
	})
	require.NoError(t, err)

	// Same asset, different case + trailing dot -> same normalized key.
	a2, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com.", Source: "scan", Confidence: 90,
	})
	require.NoError(t, err)

	assert.Equal(t, a1.ID, a2.ID, "re-import must not create a new row")
	assert.Len(t, repo.rows, 1)
	assert.Equal(t, "scan", a2.Source, "source is refreshed on re-import")
	assert.Equal(t, uint8(90), a2.Confidence, "confidence is refreshed on re-import")
}

// Acceptance: the same normalized key under two different projects yields two
// distinct rows (project isolation).
func TestImportProjectIsolation(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	a1, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com",
	})
	require.NoError(t, err)
	a2, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 2, AssetType: asset.TypeDomain, Value: "example.com",
	})
	require.NoError(t, err)

	assert.NotEqual(t, a1.ID, a2.ID)
	assert.Len(t, repo.rows, 2)

	// A project-scoped read never sees the other project's asset.
	_, err = svc.GetByID(context.Background(), 1, a2.ID)
	require.ErrorIs(t, err, asset.ErrNotFound)
}

// Invalid input is rejected before any write happens.
func TestImportRejectsInvalid(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	_, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeIP, Value: "not-an-ip",
	})
	require.ErrorIs(t, err, asset.ErrInvalidIP)
	assert.Empty(t, repo.rows, "no row is written on invalid input")

	_, err = svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 0, AssetType: asset.TypeDomain, Value: "example.com",
	})
	require.ErrorIs(t, err, asset.ErrInvalidProjectID, "missing project is rejected")
}

// Acceptance: an over-length generic (web) value whose type-prefixed key exceeds
// asset_key (VARCHAR(512)) is rejected before any repository write.
func TestImportRejectsLongKey(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	// value length passes value(1024) but "web:" + value overflows asset_key(512).
	longVal := "https://example.com/" + strings.Repeat("a", 600)
	_, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeWeb, Value: longVal,
	})
	require.ErrorIs(t, err, asset.ErrKeyTooLong)
	assert.Empty(t, repo.rows, "no row is written when the key is too long")
}

// Acceptance: a long-but-valid web asset (value fits value(1024) and the key
// fits asset_key(512), but exceeds display_name(255)) imports when DisplayName
// is omitted — the defaulted display name must not make it unimportable.
func TestImportLongValueOmittedDisplayName(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	// ~316 chars: > 255 (display_name) but < 512 (key, incl. "web:" prefix).
	longVal := "https://example.com/" + strings.Repeat("a", 296)
	require.Greater(t, len(longVal), 255)
	require.LessOrEqual(t, len("web:"+longVal), 512)

	a, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeWeb, Value: longVal,
	})
	require.NoError(t, err)
	assert.Equal(t, longVal, a.Value)
	assert.Empty(t, a.DisplayName, "over-length default display name is left empty, not rejected")

	// But an explicit over-length DisplayName is still rejected.
	_, err = svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeWeb, Value: "https://ok.example.com",
		DisplayName: strings.Repeat("d", 256),
	})
	require.ErrorIs(t, err, asset.ErrMetadataTooLong)
}

// Acceptance: over-length metadata fields are rejected before any write.
func TestImportRejectsLongMetadata(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	cases := []struct {
		name string
		in   asset.ImportInput
	}{
		{"owner", asset.ImportInput{ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com", Owner: strings.Repeat("o", 65)}},
		{"source", asset.ImportInput{ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com", Source: strings.Repeat("s", 65)}},
		{"business_unit", asset.ImportInput{ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com", BusinessUnit: strings.Repeat("b", 129)}},
		{"display_name", asset.ImportInput{ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com", DisplayName: strings.Repeat("d", 256)}},
		{"tenant_id", asset.ImportInput{ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com", TenantID: strings.Repeat("t", 65)}},
		{"org_id", asset.ImportInput{ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com", OrgID: strings.Repeat("g", 65)}},
		{"actor_id", asset.ImportInput{ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com", ActorID: strings.Repeat("a", 65)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Import(context.Background(), tc.in)
			require.ErrorIs(t, err, asset.ErrMetadataTooLong)
		})
	}
	assert.Empty(t, repo.rows, "no row is written on over-length metadata")
}

// A status outside the enum is rejected; empty status defaults to active.
func TestImportStatusEnum(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	_, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com", Status: "bogus",
	})
	require.ErrorIs(t, err, asset.ErrInvalidStatus)

	a, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, asset.StatusActive, a.Status, "empty status defaults to active")

	a, err = svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeSubdomain, Value: "api.example.com", Status: asset.StatusIgnored,
	})
	require.NoError(t, err)
	assert.Equal(t, asset.StatusIgnored, a.Status)
}

// Confidence above the max is clamped to MaxConfidence.
func TestImportClampsConfidence(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	a, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com", Confidence: 255,
	})
	require.NoError(t, err)
	assert.Equal(t, uint8(asset.MaxConfidence), a.Confidence)
}

// seedAsset inserts a live asset into the fake repo with a known id and key.
func seedAsset(f *fakeRepo, id, projectID uint64, assetKey, status string) {
	a := &asset.Asset{
		ID:        id,
		ProjectID: projectID,
		AssetType: asset.TypeDomain,
		AssetKey:  assetKey,
		Value:     assetKey[len(asset.TypeDomain)+1:],
		Status:    status,
	}
	f.rows[key(projectID, assetKey)] = a
}

// DryRun must classify rows (new / update / duplicate / invalid) WITHOUT writing.
func TestDryRunClassifiesAndDoesNotWrite(t *testing.T) {
	repo := newFakeRepo()
	seedAsset(repo, 50, 1, "domain:exists.com", asset.StatusActive)
	svc := asset.NewService(repo)

	report, err := svc.DryRun(context.Background(), 1, []asset.ImportInput{
		{AssetType: asset.TypeDomain, Value: "new.com"},                    // new
		{AssetType: asset.TypeDomain, Value: "exists.com"},                 // update (keyed in repo)
		{AssetType: asset.TypeDomain, Value: "new.com."},                   // duplicate of row 0 (normalizes to same key)
		{AssetType: asset.TypeIP, Value: "not-an-ip"},                      // invalid
		{AssetType: asset.TypeDomain, Value: "other.com", Status: "bogus"}, // invalid (bad status)
	})
	require.NoError(t, err)

	assert.Equal(t, int64(5), report.Total)
	assert.Equal(t, int64(1), report.New, "one new row")
	assert.Equal(t, int64(1), report.Update, "one update row")
	assert.Equal(t, int64(1), report.Duplicate, "one within-batch duplicate")
	assert.Equal(t, int64(2), report.Failed, "two invalid rows")
	assert.Len(t, report.Rows, 5)

	// No row was written or modified: the seeded asset is untouched and no new
	// row was created for "new.com".
	assert.Len(t, repo.rows, 1, "dry-run must not write anything")
	assert.Equal(t, asset.StatusActive, repo.rows[key(1, "domain:exists.com")].Status)

	// The duplicate row carries the normalized key but no existing id.
	dup := report.Rows[2]
	assert.Equal(t, asset.RowDuplicate, dup.Status)
	assert.Equal(t, "domain:new.com", dup.AssetKey)
	assert.Equal(t, uint64(0), dup.ExistingID)
}

// A duplicate row that also carries an invalid status must be surfaced as
// invalid (the real import would reject it), not masked as a harmless duplicate.
func TestDryRunDuplicateWithInvalidStatus(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	report, err := svc.DryRun(context.Background(), 1, []asset.ImportInput{
		{AssetType: asset.TypeDomain, Value: "example.com"},                 // new, valid
		{AssetType: asset.TypeDomain, Value: "EXAMPLE.com.", Status: "bad"}, // dup + invalid status
	})
	require.NoError(t, err)

	assert.Equal(t, int64(2), report.Total)
	assert.Equal(t, int64(1), report.New, "first row is new")
	assert.Equal(t, int64(1), report.Failed, "second row is invalid, not duplicate")
	assert.Equal(t, int64(0), report.Duplicate, "invalid status takes precedence over duplicate")

	bad := report.Rows[1]
	assert.Equal(t, asset.RowInvalid, bad.Status)
	assert.NotEmpty(t, bad.Error, "the validation error must be surfaced")
	assert.Empty(t, repo.rows, "dry-run writes nothing")
}

func TestDryRunRejectsBadProjectAndOversizedBatch(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	_, err := svc.DryRun(context.Background(), 0, []asset.ImportInput{{AssetType: asset.TypeDomain, Value: "x.com"}})
	require.ErrorIs(t, err, asset.ErrInvalidProjectID)

	big := make([]asset.ImportInput, asset.MaxImportBatch+1) // intentional overflow to trip the cap
	for i := range big {
		big[i] = asset.ImportInput{AssetType: asset.TypeDomain, Value: "x.com"}
	}
	_, err = svc.DryRun(context.Background(), 1, big)
	require.ErrorIs(t, err, asset.ErrBatchTooLarge)
}

// ImportBatch reports per-row success/failure and is idempotent.
func TestImportBatchStatsAndIdempotent(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	report, err := svc.ImportBatch(context.Background(), asset.ImportBatchInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1", ActorID: "u1",
		Rows: []asset.ImportInput{
			{AssetType: asset.TypeDomain, Value: "example.com"},
			{AssetType: asset.TypeDomain, Value: "EXAMPLE.com."}, // same normalized key -> idempotent
			{AssetType: asset.TypeIP, Value: "not-an-ip"},        // fails
		},
	}, asset.AuditMeta{})
	require.NoError(t, err)

	assert.Equal(t, int64(3), report.Total)
	assert.Equal(t, int64(2), report.Success)
	assert.Equal(t, int64(1), report.Failed)
	assert.Len(t, repo.rows, 1, "two same-key rows collapse to one")
	assert.Equal(t, asset.RowFailed, report.Rows[2].Status)
}

func TestImportBatchLinksSubdomainToProjectRoot(t *testing.T) {
	repo := newFakeRepo()
	relations := newFakeRelationRepo()
	svc := asset.NewService(repo, asset.WithRelationRepository(relations))

	root, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "example.com",
	})
	require.NoError(t, err)
	repo.rootDomainAssetIDs["1:api.example.com"] = root.ID

	report, err := svc.ImportBatch(context.Background(), asset.ImportBatchInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1", ActorID: "u1",
		Rows: []asset.ImportInput{{AssetType: asset.TypeSubdomain, Value: "api.example.com"}},
	}, asset.AuditMeta{})
	require.NoError(t, err)
	require.Equal(t, int64(1), report.Success)

	subdomain, err := repo.GetByKey(context.Background(), 1, "subdomain:api.example.com")
	require.NoError(t, err)
	relation, err := relations.GetByEndpoints(context.Background(), 1, root.ID, subdomain.ID, asset.RelationContains)
	require.NoError(t, err)
	assert.Equal(t, "project_profile", relation.Source)
	assert.Equal(t, uint8(100), relation.Confidence)
}

// Acceptance: re-importing an asset deliberately set to 'ignored' must NOT flip
// it back to 'active' (status is preserved by Upsert).
func TestImportBatchPreservesIgnoredStatus(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	// First import sets the asset, then an operator ignores it via Update.
	a, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com",
	})
	require.NoError(t, err)
	_, err = svc.Update(context.Background(), 1, a.ID, asset.UpdateFields{
		Status: ptrString(asset.StatusIgnored),
	}, "u1", asset.AuditMeta{})
	require.NoError(t, err)

	// Re-import the same asset with default (active) status.
	report, err := svc.ImportBatch(context.Background(), asset.ImportBatchInput{
		ProjectID: 1, ActorID: "u1",
		Rows: []asset.ImportInput{{AssetType: asset.TypeDomain, Value: "example.com"}},
	}, asset.AuditMeta{})
	require.NoError(t, err)
	require.Equal(t, int64(1), report.Success)

	got, err := svc.GetByID(context.Background(), 1, a.ID)
	require.NoError(t, err)
	assert.Equal(t, asset.StatusIgnored, got.Status, "re-import must not un-ignore")
}

// Update applies only the provided fields and preserves the rest.
func TestUpdatePartialMerge(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)

	a, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com",
		Source: "seed", Owner: "alice", BusinessUnit: "team-a",
	})
	require.NoError(t, err)

	after, err := svc.Update(context.Background(), 1, a.ID, asset.UpdateFields{
		Owner: ptrString("bob"),
	}, "u1", asset.AuditMeta{})
	require.NoError(t, err)

	assert.Equal(t, "bob", after.Owner, "provided field is updated")
	assert.Equal(t, "seed", after.Source, "omitted field is preserved")
	assert.Equal(t, "team-a", after.BusinessUnit, "omitted field is preserved")
	assert.Equal(t, "u1", after.UpdatedBy)
}

// Update rejects 'deleted' status (reserved for the soft-delete operation) and
// unknown statuses.
func TestUpdateRejectsDeletedStatus(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)
	a, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com",
	})
	require.NoError(t, err)

	_, err = svc.Update(context.Background(), 1, a.ID, asset.UpdateFields{
		Status: ptrString(asset.StatusDeleted),
	}, "u1", asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrInvalidStatus)

	_, err = svc.Update(context.Background(), 1, a.ID, asset.UpdateFields{
		Status: ptrString("bogus"),
	}, "u1", asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrInvalidStatus)
}

// Update on a missing or cross-project asset is NotFound (project-scoped read).
func TestUpdateNotFoundAndCrossProject(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)
	a, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com",
	})
	require.NoError(t, err)

	_, err = svc.Update(context.Background(), 1, 9999, asset.UpdateFields{Owner: ptrString("x")}, "u1", asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrNotFound)

	// Same id, wrong project -> not found (project isolation at the DB layer).
	_, err = svc.Update(context.Background(), 2, a.ID, asset.UpdateFields{Owner: ptrString("x")}, "u1", asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrNotFound)
}

func TestUpdateRejectsNoFieldsAndOverlong(t *testing.T) {
	repo := newFakeRepo()
	svc := asset.NewService(repo)
	a, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, AssetType: asset.TypeDomain, Value: "example.com",
	})
	require.NoError(t, err)

	_, err = svc.Update(context.Background(), 1, a.ID, asset.UpdateFields{}, "u1", asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrNoFields)

	_, err = svc.Update(context.Background(), 1, a.ID, asset.UpdateFields{
		Owner: ptrString(strings.Repeat("o", 65)),
	}, "u1", asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrMetadataTooLong)
}

func ptrString(s string) *string { return &s }
