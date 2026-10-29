package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeActiveResultEngine struct {
	status      EngineJobStatus
	statusErr   error
	pages       map[int]EngineResultPage
	fetchErr    map[int]error
	requested   []int
	statusCalls int
}

func (f *fakeActiveResultEngine) Dispatch(context.Context, ScanJob) (string, error) {
	return "", errors.New("not used")
}

func (f *fakeActiveResultEngine) Cancel(context.Context, string) error {
	return ErrActiveEngineCancelUnsupported
}

func (f *fakeActiveResultEngine) Status(context.Context, string) (EngineJobStatus, error) {
	f.statusCalls++
	return f.status, f.statusErr
}

func (f *fakeActiveResultEngine) FetchResultPage(
	_ context.Context,
	_ string,
	_ string,
	page int,
	_ int,
) (EngineResultPage, error) {
	f.requested = append(f.requested, page)
	if err := f.fetchErr[page]; err != nil {
		return EngineResultPage{}, err
	}
	result, ok := f.pages[page]
	if !ok {
		return EngineResultPage{}, ErrEngineResult
	}
	return result, nil
}

func activeResultTestRun(taskType string) *TaskRun {
	return &TaskRun{
		ID: 44, TenantID: "tenant-1", OrgID: "org-1", ProjectID: 7,
		TaskType: taskType, Status: TaskRunStatusRunning,
		EngineJobID: "active-job-44", TimeoutSeconds: 300,
		DispatchedAt: time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC),
		StartedAt:    time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC),
	}
}

func TestBuildActivePortResultPayloadNormalizesAndDeduplicatesPorts(t *testing.T) {
	run := activeResultTestRun(TaskTypePortProbe)
	observedAt := time.Date(2026, 7, 28, 10, 5, 0, 0, time.UTC)
	payload, targets, err := buildActiveResultPayload(run, EngineResultPage{
		TaskID: run.EngineJobID, Page: 1, PageSize: activeAPIResultPageSize,
		TotalTargets: 1, FinishedTargets: 1,
		PortResults: []EnginePortResult{{
			Target: "203.0.113.10",
			Ports:  "443，80,443",
		}},
	}, observedAt, hostClassifier{})
	require.NoError(t, err)

	assert.Equal(t, []string{"ip:203.0.113.10"}, targets)
	require.Len(t, payload.Assets, 1)
	assert.Equal(t, "ip:203.0.113.10", payload.Assets[0].NaturalKey)
	assert.True(t, *payload.Assets[0].ActiveProbe)
	assert.Equal(t, activeResultProvider, payload.Assets[0].Provider)
	assert.Equal(t, activeResultSource, payload.Assets[0].Source)

	require.Len(t, payload.Exposures, 2)
	byPort := make(map[uint32]callbackExposureV1, len(payload.Exposures))
	for _, fact := range payload.Exposures {
		byPort[fact.Port] = fact
	}
	assert.Equal(t, "tcp", byPort[80].Protocol)
	assert.Equal(t, "203.0.113.10:80", byPort[80].Value)
	assert.Equal(t, "203.0.113.10:443", byPort[443].Value)
	assert.Equal(t, uint64(3), payload.ResultCount)
}

func TestBuildActiveWebResultPayloadRedactsAndDropsSensitiveEvidence(t *testing.T) {
	run := activeResultTestRun(TaskTypeWebProbe)
	payload, targets, err := buildActiveResultPayload(run, EngineResultPage{
		TaskID: run.EngineJobID, Page: 1, PageSize: activeAPIResultPageSize,
		TotalTargets: 1, FinishedTargets: 1,
		WebResults: []EngineWebResult{{
			Target: "https://Example.com/login?access_token=must-not-persist",
			Port:   443,
			Fingerprints: []EngineWebFingerprint{
				{Name: "nginx", StatusCode: "200", Title: "Authorization: Bearer must-not-persist"},
				{Name: "React", StatusCode: "200", Title: "ignored duplicate title"},
			},
		}},
	}, time.Date(2026, 7, 28, 10, 5, 0, 0, time.UTC), hostClassifier{})
	require.NoError(t, err)

	require.Len(t, targets, 1)
	assert.NotContains(t, targets[0], "must-not-persist")
	require.Len(t, payload.Assets, 2)
	assert.Equal(t, "domain:example.com", payload.Assets[0].NaturalKey)
	require.Len(t, payload.Relations, 1)
	assert.Equal(t, "contains", payload.Relations[0].RelationType)
	assert.Equal(t, "domain:example.com", payload.Relations[0].From.NaturalKey)
	assert.Equal(t, "web:https://example.com/login", payload.Relations[0].To.NaturalKey)
	require.Len(t, payload.Exposures, 3)

	var web callbackExposureV1
	for _, fact := range payload.Exposures {
		if fact.ExposureType == "web" {
			web = fact
			break
		}
	}
	assert.Equal(t, "https://example.com/login", web.URL)
	assert.Equal(t, "[REDACTED]", web.Name)
	assert.Equal(t, "200", web.Value)
	assert.Equal(t, "React,nginx", web.Fingerprint)

	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "must-not-persist")
	assert.NotContains(t, string(raw), "poc_results")
	assert.NotContains(t, string(raw), "req_json")
	assert.NotContains(t, string(raw), "resp_json")
}

func TestBuildActiveResultPayloadRejectsInvalidProviderData(t *testing.T) {
	run := activeResultTestRun(TaskTypeFingerprint)
	_, _, err := buildActiveResultPayload(run, EngineResultPage{
		TaskID: run.EngineJobID, Page: 1,
		WebResults: []EngineWebResult{{
			Target: "https://example.com",
			Port:   80,
		}},
	}, time.Now().UTC(), hostClassifier{})
	assert.ErrorIs(t, err, ErrEngineResult, "provider port must match the URL scheme")

	_, _, err = buildActiveResultPayload(run, EngineResultPage{
		TaskID: run.EngineJobID, Page: 1,
		WebResults: []EngineWebResult{{
			Target: "https://example.com",
			Port:   443,
			Fingerprints: []EngineWebFingerprint{{
				Name: "nginx", StatusCode: "999", Title: "example",
			}},
		}},
	}, time.Now().UTC(), hostClassifier{})
	assert.ErrorIs(t, err, ErrEngineResult)
}

func TestPullActiveRunResultsPaginatesAndDeduplicatesFacts(t *testing.T) {
	run := activeResultTestRun(TaskTypePortProbe)
	engine := &fakeActiveResultEngine{pages: map[int]EngineResultPage{
		1: {
			TaskID: run.EngineJobID, Page: 1, PageSize: activeAPIResultPageSize,
			TotalTargets: 51, FinishedTargets: 51,
			PortResults: []EnginePortResult{{Target: "203.0.113.10", Ports: "443"}},
		},
		2: {
			TaskID: run.EngineJobID, Page: 2, PageSize: activeAPIResultPageSize,
			TotalTargets: 51, FinishedTargets: 51,
			PortResults: []EnginePortResult{{Target: "203.0.113.10", Ports: "443"}},
		},
	}}
	svc := NewService(newFakeRepo(), WithNow(func() time.Time {
		return time.Date(2026, 7, 28, 10, 5, 0, 0, time.UTC)
	}))
	var payloads []callbackPayload
	svc.activeResultIngestFn = func(_ context.Context, _ *TaskRun, payload callbackPayload) error {
		payloads = append(payloads, payload)
		return nil
	}

	summary, err := svc.pullActiveRunResults(context.Background(), run, engine)
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2}, engine.requested)
	assert.Len(t, payloads, 2)
	assert.Equal(t, 1, summary.TargetCount)
	assert.Equal(t, uint64(2), summary.FactCount, "asset and port exposure must be counted once")
}

func TestSplitActiveResultPageBoundsLargePortBatches(t *testing.T) {
	portText := make([]string, 0, 600)
	for port := 1; port <= 600; port++ {
		portText = append(portText, strconv.Itoa(port))
	}
	results := make([]EnginePortResult, 0, 3)
	for index := 0; index < 3; index++ {
		results = append(results, EnginePortResult{
			Target: fmt.Sprintf("203.0.113.%d", index+1),
			Ports:  strings.Join(portText, ","),
		})
	}
	batches, err := splitActiveResultPage(TaskTypePortProbe, EngineResultPage{
		TaskID: "job-1", Page: 1, PageSize: activeAPIResultPageSize,
		TotalTargets: 3, FinishedTargets: 3, PortResults: results,
	})
	require.NoError(t, err)
	require.Len(t, batches, 2)
	assert.Len(t, batches[0].PortResults, 2)
	assert.Len(t, batches[1].PortResults, 1)
}

func TestReconcileActiveSuccessPullsResultsBeforeTerminalTransition(t *testing.T) {
	run := activeResultTestRun(TaskTypeWebProbe)
	repo := newFakeRepo()
	repo.runs[run.ProjectID] = map[uint64]*TaskRun{run.ID: run}
	engine := &fakeActiveResultEngine{
		status: EngineJobStatus{Status: EngineJobStatusSuccess},
		pages: map[int]EngineResultPage{
			1: {
				TaskID: run.EngineJobID, Page: 1, PageSize: activeAPIResultPageSize,
				TotalTargets: 1, FinishedTargets: 1,
				WebResults: []EngineWebResult{{
					Target: "https://example.com", Port: 443,
					Fingerprints: []EngineWebFingerprint{{
						Name: "nginx", StatusCode: "200", Title: "Example",
					}},
				}},
			},
		},
	}
	svc := NewService(repo, WithEngineAdapter(engine), WithNow(func() time.Time {
		return time.Date(2026, 7, 28, 10, 5, 0, 0, time.UTC)
	}))
	ingestCalls := 0
	svc.activeResultIngestFn = func(_ context.Context, gotRun *TaskRun, payload callbackPayload) error {
		ingestCalls++
		assert.Equal(t, run.ProjectID, gotRun.ProjectID)
		assert.Equal(t, run.ID, payload.RunID)
		return nil
	}

	after, err := svc.ReconcileTaskRun(context.Background(), ReconcileTaskRunInput{
		ProjectID: run.ProjectID, RunID: run.ID, ActorID: "scheduler",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, ingestCalls)
	assert.Equal(t, TaskRunStatusSuccess, after.Status)
	assert.Equal(t, uint64(5), after.ResultCount)
}

func TestReconcileActiveSuccessRefusesIncompleteTargetSet(t *testing.T) {
	run := activeResultTestRun(TaskTypePortProbe)
	repo := newFakeRepo()
	repo.runs[run.ProjectID] = map[uint64]*TaskRun{run.ID: run}
	engine := &fakeActiveResultEngine{
		status: EngineJobStatus{Status: EngineJobStatusSuccess},
		pages: map[int]EngineResultPage{
			1: {
				TaskID: run.EngineJobID, Page: 1, PageSize: activeAPIResultPageSize,
				TotalTargets: 2, FinishedTargets: 2,
				PortResults: []EnginePortResult{{Target: "203.0.113.10", Ports: ""}},
			},
		},
	}
	svc := NewService(repo, WithEngineAdapter(engine))
	svc.activeResultIngestFn = func(context.Context, *TaskRun, callbackPayload) error {
		return nil
	}

	_, err := svc.ReconcileTaskRun(context.Background(), ReconcileTaskRunInput{
		ProjectID: run.ProjectID, RunID: run.ID, ActorID: "scheduler",
	})
	assert.ErrorIs(t, err, ErrEngineResultIncomplete)
	stored, getErr := repo.GetTaskRun(context.Background(), run.ProjectID, run.ID)
	require.NoError(t, getErr)
	assert.Equal(t, TaskRunStatusRunning, stored.Status)
}

func TestReconcileActivePartialSuccessMaterializesAvailableResults(t *testing.T) {
	run := activeResultTestRun(TaskTypePortProbe)
	repo := newFakeRepo()
	repo.runs[run.ProjectID] = map[uint64]*TaskRun{run.ID: run}
	engine := &fakeActiveResultEngine{
		status: EngineJobStatus{Status: EngineJobStatusPartialSuccess},
		pages: map[int]EngineResultPage{
			1: {
				TaskID: run.EngineJobID, Page: 1, PageSize: activeAPIResultPageSize,
				TotalTargets: 2, FinishedTargets: 1,
				PortResults: []EnginePortResult{{Target: "203.0.113.10", Ports: "443"}},
			},
		},
	}
	svc := NewService(repo, WithEngineAdapter(engine))
	svc.activeResultIngestFn = func(context.Context, *TaskRun, callbackPayload) error {
		return nil
	}

	after, err := svc.ReconcileTaskRun(context.Background(), ReconcileTaskRunInput{
		ProjectID: run.ProjectID, RunID: run.ID, ActorID: "scheduler",
	})
	require.NoError(t, err)
	assert.Equal(t, TaskRunStatusPartial, after.Status)
	assert.Equal(t, uint64(2), after.ResultCount)
}

func TestReconcileActiveResultIsProjectScoped(t *testing.T) {
	run := activeResultTestRun(TaskTypePortProbe)
	repo := newFakeRepo()
	repo.runs[run.ProjectID] = map[uint64]*TaskRun{run.ID: run}
	engine := &fakeActiveResultEngine{
		status: EngineJobStatus{Status: EngineJobStatusSuccess},
		pages:  map[int]EngineResultPage{},
	}
	svc := NewService(repo, WithEngineAdapter(engine))
	svc.activeResultIngestFn = func(context.Context, *TaskRun, callbackPayload) error {
		t.Fatal("cross-project lookup must fail before result ingest")
		return nil
	}

	_, err := svc.ReconcileTaskRun(context.Background(), ReconcileTaskRunInput{
		ProjectID: run.ProjectID + 1, RunID: run.ID, ActorID: "scheduler",
	})
	assert.ErrorIs(t, err, ErrNotFound)
	assert.Zero(t, engine.statusCalls)
	assert.Empty(t, engine.requested)
}

func TestReconcileRunningRunsPollsNonTimedOutJobs(t *testing.T) {
	run := activeResultTestRun(TaskTypePortProbe)
	repo := newFakeRepo()
	repo.runs[run.ProjectID] = map[uint64]*TaskRun{run.ID: run}
	engine := &fakeActiveResultEngine{
		status: EngineJobStatus{Status: EngineJobStatusRunning},
		pages:  map[int]EngineResultPage{},
	}
	now := run.DispatchedAt.Add(time.Minute)
	svc := NewService(
		repo,
		WithEngineAdapter(engine),
		WithNow(func() time.Time { return now }),
	)

	result, err := svc.ReconcileRunningRuns(context.Background(), ReconcileRunningRunsInput{
		Limit: 10, ActorID: "scheduler",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Checked)
	assert.Zero(t, result.Updated)
	assert.Equal(t, 1, engine.statusCalls)
}

func TestReconcileRunningRunsReportsFailedRunIDsWithoutExposingEngineDetails(t *testing.T) {
	run := activeResultTestRun(TaskTypePortProbe)
	repo := newFakeRepo()
	repo.runs[run.ProjectID] = map[uint64]*TaskRun{run.ID: run}
	engine := &fakeActiveResultEngine{
		statusErr: errors.New("sensitive upstream detail"),
		pages:     map[int]EngineResultPage{},
	}
	svc := NewService(repo, WithEngineAdapter(engine))

	result, err := svc.ReconcileRunningRuns(context.Background(), ReconcileRunningRunsInput{
		Limit: 10, ActorID: "scheduler",
	})
	require.Error(t, err)
	assert.Equal(t, []uint64{run.ID}, result.FailedRunIDs)
	require.Len(t, result.Errors, 1)
	assert.NotContains(t, fmt.Sprint(result.FailedRunIDs), "sensitive upstream detail")
}
