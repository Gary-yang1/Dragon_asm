package discovery

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var observationCols = []string{
	"id", "tenant_id", "org_id", "project_id", "run_id", "seq", "kind", "natural_key", "client_ref",
	"provider", "capability", "observed_at", "confidence", "active_probe", "evidence_hash", "evidence_ref",
	"normalized_json", "normalized_size", "ingest_status", "ingest_error", "created_at", "updated_at", "deleted_at",
}

func validObservation(now time.Time) DiscoveryObservation {
	return DiscoveryObservation{
		TenantID: " t1 ", OrgID: " o1 ", ProjectID: 7, RunID: 9, Seq: 2,
		Kind: "ASSET", NaturalKey: " API.Example.COM ", ClientRef: "asset-1",
		Provider: " CRTSH ", Capability: " SUBDOMAIN_PASSIVE ", ObservedAt: now,
		Confidence: 90, EvidenceHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EvidenceRef: "provider:item:1", NormalizedJSON: []byte(`{"asset_type":"subdomain","value":"api.example.com"}`),
	}
}

func TestObservationNormalizationAndSensitiveDataRejection(t *testing.T) {
	now := time.Now().UTC()
	normalized, err := normalizeDiscoveryObservation(validObservation(now))
	require.NoError(t, err)
	assert.Equal(t, "api.example.com", normalized.NaturalKey)
	assert.Equal(t, "crtsh", normalized.Provider)
	assert.Equal(t, "subdomain_passive", normalized.Capability)
	assert.Equal(t, ObservationStatusObserved, normalized.IngestStatus)
	assert.Equal(t, uint32(len(normalized.NormalizedJSON)), normalized.NormalizedSize)

	bad := validObservation(now)
	bad.NormalizedJSON = []byte(`{"authorization":"Bearer redacted"}`)
	_, err = normalizeDiscoveryObservation(bad)
	assert.ErrorIs(t, err, ErrInvalidDiscoveryObservation)

	bad = validObservation(now)
	bad.NormalizedJSON = make([]byte, maxObservationJSONBytes+1)
	_, err = normalizeDiscoveryObservation(bad)
	assert.ErrorIs(t, err, ErrInvalidDiscoveryObservation)
}

func TestRepoUpsertObservationUsesProjectScopedRead(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	now := time.Now().UTC()
	in := validObservation(now)
	normalized, err := normalizeDiscoveryObservation(in)
	require.NoError(t, err)

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO discovery_observation")).WithArgs(
		"t1", "o1", uint64(7), uint64(9), uint64(2), ObservationKindAsset, "api.example.com", "asset-1",
		"crtsh", "subdomain_passive", now, uint8(90), false,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "provider:item:1",
		normalized.NormalizedJSON, normalized.NormalizedSize, ObservationStatusObserved, "",
	).WillReturnResult(sqlmock.NewResult(41, 1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, org_id, project_id, run_id, seq, kind, natural_key, client_ref, provider, capability, observed_at, confidence, active_probe, evidence_hash, evidence_ref, normalized_json, normalized_size, ingest_status, ingest_error, created_at, updated_at, deleted_at FROM discovery_observation")).
		WithArgs(uint64(41), uint64(7)).
		WillReturnRows(sqlmock.NewRows(observationCols).AddRow(
			uint64(41), "t1", "o1", uint64(7), uint64(9), uint64(2), ObservationKindAsset, "api.example.com", "asset-1",
			"crtsh", "subdomain_passive", now, uint8(90), false,
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "provider:item:1",
			normalized.NormalizedJSON, normalized.NormalizedSize, ObservationStatusObserved, "", now, now, time.Time{},
		))

	repo := NewRepository(dbgen.New(sqlDB))
	created, err := repo.UpsertDiscoveryObservation(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, uint64(41), created.ID)
	assert.Equal(t, uint64(7), created.ProjectID)
	assert.Equal(t, "crtsh", created.Provider)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestObservationFakeRepoPreservesProvidersAndIdempotency(t *testing.T) {
	repo := newFakeRepo()
	now := time.Now().UTC()
	first, err := repo.UpsertDiscoveryObservation(context.Background(), validObservation(now))
	require.NoError(t, err)
	retry, err := repo.UpsertDiscoveryObservation(context.Background(), validObservation(now.Add(time.Minute)))
	require.NoError(t, err)
	assert.Equal(t, first.ID, retry.ID)

	secondInput := validObservation(now)
	secondInput.Provider = "dnsdb"
	second, err := repo.UpsertDiscoveryObservation(context.Background(), secondInput)
	require.NoError(t, err)
	assert.NotEqual(t, first.ID, second.ID)
	items, err := repo.ListDiscoveryObservationsByNaturalKey(context.Background(), 7, ObservationKindAsset, "API.EXAMPLE.COM")
	require.NoError(t, err)
	assert.Len(t, items, 2)
	_, err = repo.GetDiscoveryObservation(context.Background(), 8, first.ID)
	assert.ErrorIs(t, err, ErrNotFound)
}
