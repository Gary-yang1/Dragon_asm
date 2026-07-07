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
	rows   map[string]*asset.Asset
	nextID uint64
}

func newFakeRepo() *fakeRepo { return &fakeRepo{rows: map[string]*asset.Asset{}} }

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
		return a, nil
	}
	return nil, asset.ErrNotFound
}

func (f *fakeRepo) GetByID(_ context.Context, projectID, id uint64) (*asset.Asset, error) {
	for _, a := range f.rows {
		if a.ProjectID == projectID && a.ID == id {
			return a, nil
		}
	}
	return nil, asset.ErrNotFound
}

func (f *fakeRepo) List(_ context.Context, projectID uint64, _, _ int32) ([]*asset.Asset, error) {
	var out []*asset.Asset
	for _, a := range f.rows {
		if a.ProjectID == projectID {
			out = append(out, a)
		}
	}
	return out, nil
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
