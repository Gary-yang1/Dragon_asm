package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

// fakeRepo captures inserted events and optionally injects errors.
type fakeRepo struct {
	captured []audit.Event
	err      error
}

func (f *fakeRepo) Insert(_ context.Context, e audit.Event) error {
	if f.err != nil {
		return f.err
	}
	f.captured = append(f.captured, e)
	return nil
}

func TestServiceRecordSuccess(t *testing.T) {
	repo := &fakeRepo{}
	svc := audit.NewService(repo)

	err := svc.Record(context.Background(), audit.Event{
		TenantID:  "t1",
		ActorID:   "user1",
		Action:    "project.create",
		ProjectID: 42,
		Result:    audit.ResultSuccess,
	})

	require.NoError(t, err)
	require.Len(t, repo.captured, 1)
	assert.Equal(t, "project.create", repo.captured[0].Action)
	assert.Equal(t, uint64(42), repo.captured[0].ProjectID)
}

func TestServiceRecordReturnsRepoError(t *testing.T) {
	wantErr := errors.New("db unavailable")
	repo := &fakeRepo{err: wantErr}
	svc := audit.NewService(repo)

	err := svc.Record(context.Background(), audit.Event{Action: "login.attempt"})

	require.ErrorIs(t, err, wantErr)
}

func TestServiceRecordDefaultsActorType(t *testing.T) {
	repo := &fakeRepo{}
	svc := audit.NewService(repo)
	require.NoError(t, svc.Record(context.Background(), audit.Event{Action: "login"}))
	assert.Equal(t, audit.ActorUser, repo.captured[0].ActorType)
}

func TestServiceRecordDefaultsResult(t *testing.T) {
	repo := &fakeRepo{}
	svc := audit.NewService(repo)
	require.NoError(t, svc.Record(context.Background(), audit.Event{Action: "login"}))
	assert.Equal(t, audit.ResultSuccess, repo.captured[0].Result)
}

func TestServiceRecordPreservesExplicitActorType(t *testing.T) {
	repo := &fakeRepo{}
	svc := audit.NewService(repo)
	require.NoError(t, svc.Record(context.Background(), audit.Event{
		Action:    "cron.sweep",
		ActorType: audit.ActorSystem,
	}))
	assert.Equal(t, audit.ActorSystem, repo.captured[0].ActorType)
}

func TestServiceRecordPreservesExplicitFailure(t *testing.T) {
	repo := &fakeRepo{}
	svc := audit.NewService(repo)
	require.NoError(t, svc.Record(context.Background(), audit.Event{
		Action: "login.attempt",
		Result: audit.ResultFailure,
	}))
	assert.Equal(t, audit.ResultFailure, repo.captured[0].Result)
}

func TestServiceRecordPlatformEvent(t *testing.T) {
	repo := &fakeRepo{}
	svc := audit.NewService(repo)
	// ProjectID = 0 is a valid platform-level event; must not be rejected.
	require.NoError(t, svc.Record(context.Background(), audit.Event{
		Action:    "user.login",
		ProjectID: 0,
	}))
	assert.Equal(t, uint64(0), repo.captured[0].ProjectID)
}
