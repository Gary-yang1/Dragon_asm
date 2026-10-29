package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type routerTestAdapter struct {
	dispatchID    string
	dispatchErr   error
	dispatchCalls int
	cancelCalls   int
	statusCalls   int
}

func TestValidateEngineProjectRejectsMissingBinding(t *testing.T) {
	adapter := &ActiveAPIEngineAdapter{projectIDs: map[uint64]int{1: 10}}
	svc := &Service{engine: adapter}
	require.NoError(t, svc.validateEngineProject(1, TaskTypeWebProbe))
	require.ErrorIs(t, svc.validateEngineProject(5, TaskTypeWebProbe), ErrActiveEngineProjectMapping)
	// The ASM project ID must never be silently reused as an engine project ID.
	require.ErrorIs(t, svc.validateEngineProject(10, TaskTypeWebProbe), ErrActiveEngineProjectMapping)
}

func (a *routerTestAdapter) Dispatch(context.Context, ScanJob) (string, error) {
	a.dispatchCalls++
	return a.dispatchID, a.dispatchErr
}

func (a *routerTestAdapter) Cancel(context.Context, string) error {
	a.cancelCalls++
	return nil
}

func (a *routerTestAdapter) Status(context.Context, string) (EngineJobStatus, error) {
	a.statusCalls++
	return EngineJobStatus{Status: EngineJobStatusRunning}, nil
}

func TestEngineRouteForTaskTypeMatrix(t *testing.T) {
	tests := []struct {
		taskType string
		want     EngineRoute
	}{
		{TaskTypePassiveIntel, EngineRoutePassive},
		{TaskTypeDNS, EngineRoutePassive},
		{TaskTypeOrgIntel, EngineRoutePassive},
		{TaskTypePortProbe, EngineRouteActive},
		{TaskTypeWebProbe, EngineRouteActive},
		{TaskTypeFingerprint, EngineRouteActive},
	}
	for _, test := range tests {
		t.Run(test.taskType, func(t *testing.T) {
			got, err := EngineRouteForTaskType(test.taskType)
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}

	for _, taskType := range []string{TaskTypeDirScan, TaskTypeCTLog, "unknown"} {
		t.Run("unsupported/"+taskType, func(t *testing.T) {
			_, err := EngineRouteForTaskType(taskType)
			assert.ErrorIs(t, err, ErrEngineRouteUnsupported)
			assert.ErrorIs(t, err, ErrEngineJobRejected)
		})
	}
}

func TestTaskTypeEngineRouterDoesNotFallBackWhenRouteIsMissing(t *testing.T) {
	passive := &routerTestAdapter{}
	router := NewTaskTypeEngineRouter(passive, nil)

	_, err := router.EngineForTaskType(TaskTypeWebProbe)
	assert.ErrorIs(t, err, ErrEngineNotConfigured)
	assert.Zero(t, passive.dispatchCalls)

	active := &routerTestAdapter{}
	router = NewTaskTypeEngineRouter(nil, active)
	_, err = router.EngineForTaskType(TaskTypeDNS)
	assert.ErrorIs(t, err, ErrEngineNotConfigured)
	assert.Zero(t, active.dispatchCalls)
}

func TestTaskTypeEngineRouterDoesNotFallBackAfterAdapterFailure(t *testing.T) {
	engineFailure := errors.New("active engine unavailable")
	passive := &routerTestAdapter{dispatchID: "passive-job"}
	active := &routerTestAdapter{dispatchErr: engineFailure}
	router := NewTaskTypeEngineRouter(passive, active)

	selected, err := router.EngineForTaskType(TaskTypePortProbe)
	require.NoError(t, err)
	_, err = selected.Dispatch(context.Background(), ScanJob{JobType: TaskTypePortProbe})
	assert.ErrorIs(t, err, engineFailure)
	assert.Equal(t, 1, active.dispatchCalls)
	assert.Zero(t, passive.dispatchCalls)
}

func TestServiceEngineSelectionPrefersRouterOverLegacyAdapter(t *testing.T) {
	legacy := &routerTestAdapter{}
	passive := &routerTestAdapter{}
	active := &routerTestAdapter{}
	service := NewService(
		nil,
		WithEngineAdapter(legacy),
		WithEngineRouter(NewTaskTypeEngineRouter(passive, active)),
	)

	selected, err := service.engineForTaskType(TaskTypeWebProbe)
	require.NoError(t, err)
	require.Same(t, active, selected)

	_, err = selected.Status(context.Background(), "active-task-1")
	require.NoError(t, err)
	assert.Equal(t, 1, active.statusCalls)
	assert.Zero(t, passive.statusCalls)
	assert.Zero(t, legacy.statusCalls)
}

func TestServiceRoutesActiveRunStatusAndCancellationToActiveEngine(t *testing.T) {
	repo := newFakeRepo()
	repo.runs[1] = map[uint64]*TaskRun{
		10: {
			ID:          10,
			ProjectID:   1,
			TaskType:    TaskTypeWebProbe,
			Status:      TaskRunStatusRunning,
			EngineJobID: "active-task-10",
		},
	}
	passive := &routerTestAdapter{}
	active := &routerTestAdapter{}
	service := NewService(
		repo,
		WithEngineRouter(NewTaskTypeEngineRouter(passive, active)),
	)

	run, err := service.ReconcileTaskRun(context.Background(), ReconcileTaskRunInput{
		ProjectID: 1,
		RunID:     10,
		ActorID:   "operator-1",
	})
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusRunning, run.Status)
	assert.Equal(t, 1, active.statusCalls)
	assert.Zero(t, passive.statusCalls)

	err = service.CancelDispatchedTaskRun(context.Background(), UpdateTaskRunStatusInput{
		ProjectID: 1,
		RunID:     10,
		ActorID:   "operator-1",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, active.cancelCalls)
	assert.Zero(t, passive.cancelCalls)
	assert.Equal(t, TaskRunStatusCancelled, repo.runs[1][10].Status)
}

func TestConfiguredEngineRouterIsolatesConfigurationFailures(t *testing.T) {
	router, status := NewConfiguredEngineRouter(EngineRouterConfig{
		PassiveBaseURL:  "https://passive.example.com",
		PassiveToken:    "passive-token",
		ActiveBaseURL:   "https://active.example.com",
		ActiveAccessKey: "ak_example",
		// Deliberately too short.
		ActiveSecretKey:  "short",
		ActiveProjectMap: `{"1": 9}`,
	}, nil, nil)

	assert.True(t, status.Passive.Configured)
	assert.True(t, status.Passive.Ready)
	assert.NoError(t, status.Passive.Err)
	assert.True(t, status.Active.Configured)
	assert.False(t, status.Active.Ready)
	assert.ErrorIs(t, status.Active.Err, ErrEngineNotConfigured)

	_, err := router.EngineForTaskType(TaskTypeDNS)
	require.NoError(t, err)
	_, err = router.EngineForTaskType(TaskTypeWebProbe)
	assert.ErrorIs(t, err, ErrEngineNotConfigured)
}

func TestConfiguredEngineRouterBuildsBothRoutes(t *testing.T) {
	router, status := NewConfiguredEngineRouter(EngineRouterConfig{
		PassiveBaseURL:   "https://passive.example.com",
		PassiveToken:     "passive-token",
		ActiveBaseURL:    "https://active.example.com",
		ActiveAccessKey:  "ak_example",
		ActiveSecretKey:  strings.Repeat("s", activeAPIMinSecretKeyLen),
		ActiveProjectMap: `{"1": 9, "2": 10}`,
	}, nil, nil)

	assert.True(t, status.Passive.Ready)
	assert.True(t, status.Active.Ready)
	_, err := router.EngineForTaskType(TaskTypePassiveIntel)
	require.NoError(t, err)
	_, err = router.EngineForTaskType(TaskTypePortProbe)
	require.NoError(t, err)
}

func TestParseActiveEngineProjectMapRejectsInvalidInput(t *testing.T) {
	for _, raw := range []string{
		"null",
		`{"0": 1}`,
		`{"1": 0}`,
		`{"one": 1}`,
		`{"1": 1} trailing`,
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := parseActiveEngineProjectMap(raw)
			assert.ErrorIs(t, err, ErrEngineNotConfigured)
		})
	}
}

func TestActiveEngineAllowsAutomaticProjectMapping(t *testing.T) {
	for _, raw := range []string{"", "{}", "{ }"} {
		_, status := NewConfiguredEngineRouter(EngineRouterConfig{ActiveBaseURL: "https://engine.example.com", ActiveAccessKey: "ak", ActiveSecretKey: activeAPITestSecret, ActiveProjectMap: raw}, nil, nil)
		require.True(t, status.Active.Ready, raw)
	}
}
