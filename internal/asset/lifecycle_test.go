package asset_test

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// newLifecycleService builds a Service over an in-memory repo with a fake audit
// sink so lifecycle transitions are audited on the non-tx path.
func newLifecycleService(t *testing.T, opts ...asset.ServiceOption) (*asset.Service, *fakeRepo, *fakeAudit) {
	t.Helper()
	repo := newFakeRepo()
	auditSink := &fakeAudit{}
	all := append([]asset.ServiceOption{asset.WithAuditSink(auditSink)}, opts...)
	svc := asset.NewService(repo, all...)
	return svc, repo, auditSink
}

// importActive seeds one active asset in project 1 and returns its id.
func importActive(t *testing.T, svc *asset.Service) uint64 {
	t.Helper()
	a, err := svc.Import(context.Background(), asset.ImportInput{
		ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "a.example.com",
	})
	require.NoError(t, err)
	return a.ID
}

// Below the threshold, a miss only increments miss_count — no transition, no audit.
func TestRecordMissBelowThreshold(t *testing.T) {
	svc, _, audit := newLifecycleService(t) // default threshold 3
	id := importActive(t, svc)
	ctx := context.Background()

	a, transitioned, err := svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)
	assert.False(t, transitioned)
	assert.Equal(t, uint32(1), a.MissCount)
	assert.Equal(t, asset.StatusActive, a.Status)
	assert.Empty(t, audit.events, "no audit for a non-transition miss")
}

// N consecutive misses transition active -> inactive; the transition is audited
// and miss_count is preserved at N.
func TestRecordMissTransitionsToInactive(t *testing.T) {
	svc, _, audit := newLifecycleService(t)
	id := importActive(t, svc)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		_, _, err := svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
		require.NoError(t, err)
	}
	a, err := svc.GetByID(ctx, 1, id)
	require.NoError(t, err)
	assert.Equal(t, asset.StatusInactive, a.Status)
	assert.Equal(t, uint32(3), a.MissCount)

	require.Len(t, audit.events, 1, "only the transition is audited")
	assert.Equal(t, asset.ActionAssetLifecycle, audit.events[0].Action)
	assert.Equal(t, "discovery", audit.events[0].ActorID)
}

// A configurable threshold is honoured.
func TestRecordMissConfigurableThreshold(t *testing.T) {
	svc, _, audit := newLifecycleService(t, asset.WithMissThreshold(2))
	id := importActive(t, svc)
	ctx := context.Background()

	_, _, err := svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)
	a, transitioned, err := svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)
	assert.True(t, transitioned, "threshold 2 transitions on the 2nd miss")
	assert.Equal(t, asset.StatusInactive, a.Status)
	assert.Equal(t, uint32(2), a.MissCount)
	assert.Len(t, audit.events, 1)
}

// A threshold above MaxMissThreshold is clamped, not truncated: a value that
// would wrap uint32 (4294967297 -> 1) must NOT trigger a premature transition on
// the first miss. This is the overflow boundary the review required.
func TestRecordMissThresholdClamped(t *testing.T) {
	// 4294967297 = 2^32+1: uint32() truncates to 1 without clamping, which would
	// transition on the 1st miss. With the clamp to MaxMissThreshold (1000) the
	// asset stays active through several misses.
	svc, _, audit := newLifecycleService(t, asset.WithMissThreshold(4294967297))
	id := importActive(t, svc)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		a, transitioned, err := svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
		require.NoError(t, err)
		assert.False(t, transitioned, "clamped threshold must not transition on a few misses")
		assert.Equal(t, asset.StatusActive, a.Status)
	}
	assert.Empty(t, audit.events, "no transition audited under the clamped threshold")
}

// RecordMiss on a non-active asset is a no-op (no double transition, no audit).
func TestRecordMissNonActiveNoOp(t *testing.T) {
	svc, repo, audit := newLifecycleService(t) // default threshold 3
	id := importActive(t, svc)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		_, _, err := svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
		require.NoError(t, err)
	}
	require.Len(t, audit.events, 1, "one transition audited")

	for i := 0; i < 3; i++ {
		a, transitioned, err := svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
		require.NoError(t, err)
		assert.False(t, transitioned, "no double transition on an inactive asset")
		assert.Equal(t, asset.StatusInactive, a.Status)
	}
	assert.Len(t, audit.events, 1, "no extra audit for misses on an inactive asset")
	assert.Equal(t, uint32(3), repo.rows[key(1, "domain:a.example.com")].MissCount, "miss_count frozen after transition")
}

// A hit re-activates a stale (inactive) asset, resets miss_count, and audits.
func TestRecordHitReactivates(t *testing.T) {
	svc, _, audit := newLifecycleService(t, asset.WithMissThreshold(1))
	id := importActive(t, svc)
	ctx := context.Background()

	_, _, err := svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)
	require.Len(t, audit.events, 1)

	a, transitioned, err := svc.RecordHit(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)
	assert.True(t, transitioned)
	assert.Equal(t, asset.StatusActive, a.Status)
	assert.Equal(t, uint32(0), a.MissCount)

	require.Len(t, audit.events, 2)
	assert.Equal(t, asset.StatusInactive, audit.events[1].Before.(*asset.Asset).Status)
}

// A hit on an active asset with accumulated misses resets miss_count (no
// transition, no audit); with miss_count already 0 it is a no-op.
func TestRecordHitActiveResetsMiss(t *testing.T) {
	svc, _, audit := newLifecycleService(t)
	id := importActive(t, svc)
	ctx := context.Background()

	_, _, err := svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)
	_, _, err = svc.RecordMiss(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)

	a, transitioned, err := svc.RecordHit(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)
	assert.False(t, transitioned)
	assert.Equal(t, asset.StatusActive, a.Status)
	assert.Equal(t, uint32(0), a.MissCount, "hit resets miss_count")
	assert.Empty(t, audit.events, "no audit on a non-transition hit")

	_, transitioned, err = svc.RecordHit(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)
	assert.False(t, transitioned)
}

// A hit on an ignored/deleted asset preserves its status (no un-ignore/un-delete).
func TestRecordHitPreservesIgnoredDeleted(t *testing.T) {
	svc, repo, _ := newLifecycleService(t)
	id := importActive(t, svc)
	ctx := context.Background()
	_, err := svc.Update(ctx, 1, id, asset.UpdateFields{Status: ptrString(asset.StatusIgnored)}, "ops", asset.AuditMeta{})
	require.NoError(t, err)

	a, transitioned, err := svc.RecordHit(ctx, 1, id, "discovery", asset.AuditMeta{})
	require.NoError(t, err)
	assert.False(t, transitioned)
	assert.Equal(t, asset.StatusIgnored, a.Status, "ignored is preserved on a hit")
	assert.Equal(t, uint32(0), repo.rows[key(1, "domain:a.example.com")].MissCount)
}

// Cross-project: recording a miss for an asset that lives in another project is
// ErrNotFound (project-scoped read), not a silent cross-project transition.
func TestLifecycleCrossProjectIsolation(t *testing.T) {
	svc, _, _ := newLifecycleService(t)
	ctx := context.Background()
	a, err := svc.Import(ctx, asset.ImportInput{ProjectID: 1, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "a.example.com"})
	require.NoError(t, err)
	_, err = svc.Import(ctx, asset.ImportInput{ProjectID: 2, TenantID: "t1", OrgID: "o1", AssetType: asset.TypeDomain, Value: "b.example.com"})
	require.NoError(t, err)

	_, _, err = svc.RecordMiss(ctx, 2, a.ID, "discovery", asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrNotFound)
	_, _, err = svc.RecordHit(ctx, 2, a.ID, "discovery", asset.AuditMeta{})
	require.ErrorIs(t, err, asset.ErrNotFound)
}

// An audit-write failure on a lifecycle transition rolls the asset write back:
// the transition and its audit are atomic on the transactional path.
func TestRecordMissAuditFailureRollsBack(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	svc := asset.NewService(
		asset.NewRepository(dbgen.New(sqlDB)),
		asset.WithDB(sqlDB),
		asset.WithMissThreshold(1),
	)

	mock.ExpectBegin()
	// before read: active asset
	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = ? AND project_id = ?")).WithArgs(anyArgs(2)...).
		WillReturnRows(assetRow(7, 1, "domain:a.example.com"))
	// lifecycle update: miss_count=1, status=inactive
	mock.ExpectExec(regexp.QuoteMeta("UPDATE asset")).WithArgs(anyArgs(5)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// after read
	mock.ExpectQuery(regexp.QuoteMeta("WHERE id = ? AND project_id = ?")).WithArgs(anyArgs(2)...).
		WillReturnRows(assetRow(7, 1, "domain:a.example.com"))
	// audit insert fails -> rollback (asset update rolled back with it)
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).WithArgs(anyArgs(17)...).
		WillReturnError(errors.New("audit store down"))
	mock.ExpectRollback()

	_, transitioned, err := svc.RecordMiss(context.Background(), 1, 7, "discovery", asset.AuditMeta{})
	require.Error(t, err, "audit failure must surface as an error, not a silent un-audited transition")
	assert.False(t, transitioned)
	require.NoError(t, mock.ExpectationsWereMet(), "Rollback must be called (no Commit)")
}
