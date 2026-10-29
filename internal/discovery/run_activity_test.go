package discovery

import (
	"context"
	"encoding/json"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestStageProgressValidationRejectsInvalidCounters(t *testing.T) {
	p := StageProgress{Stage: "dns", Provider: "dns", Status: "running", Total: 10, Completed: 5}
	require.True(t, validStageProgress(p))
	p.Completed = 11
	require.False(t, validStageProgress(p))
	p.Completed = 5
	p.Status = "invented"
	require.False(t, validStageProgress(p))
}
func TestPartialCallbackPersistsProviderErrorSummary(t *testing.T) {
	svc, run, now := runningCallbackFixture(t)
	raw := validCallbackRaw(t, run.ID, 1, CallbackPhaseCompleted, TaskRunStatusPartial, 0)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	body["provider_errors"] = []any{map[string]any{"provider": "dns", "code": "DNS_PARTIAL_FAILURE", "message": "DNS incomplete", "retryable": true}}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	_, err = svc.HandleCallback(context.Background(), signedCallbackInput(1, run.ID, 1, now, "secret", raw))
	require.NoError(t, err)
	_, err = svc.ClaimDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	_, err = svc.CompleteDiscoveryCallbackIngest(context.Background(), 1, run.ID, 1)
	require.NoError(t, err)
	after, err := svc.GetTaskRun(context.Background(), 1, run.ID)
	require.NoError(t, err)
	require.Equal(t, "dns: DNS_PARTIAL_FAILURE", after.ErrorSummary)
}
func TestActivityReadsLatestStageAndDeduplicatesRecentAssets(t *testing.T) {
	svc, run, _ := runningCallbackFixture(t)
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	svc.db = db
	mock.ExpectQuery("SELECT COUNT\\(\\*\\)").WithArgs(callbackMaxIngestAttempts, callbackMaxIngestAttempts, uint64(1), run.ID).WillReturnRows(sqlmock.NewRows([]string{"received", "processed", "failed", "retrying"}).AddRow(4, 1, 1, 2))
	mock.ExpectQuery("SELECT COALESCE\\(CAST").WithArgs(uint64(1), run.ID).WillReturnRows(sqlmock.NewRows([]string{"progress", "errors"}).AddRow(`{"stage":"collect","provider":"fofa","status":"success","discovered":2}`, `[]`).AddRow(`{"stage":"collect","provider":"fofa","status":"running","discovered":1}`, `[]`))
	mock.ExpectQuery("SELECT COUNT\\(DISTINCT").WithArgs(uint64(1), run.ID).WillReturnRows(sqlmock.NewRows([]string{"assets", "subdomains", "ips"}).AddRow(1, 1, 0))
	mock.ExpectQuery("SELECT provider,normalized_json,observed_at").WithArgs(uint64(1), run.ID).WillReturnRows(sqlmock.NewRows([]string{"provider", "json", "at"}).AddRow("dns", `{"asset_type":"subdomain","value":"a.example.com","attributes":{"dns_status":"no_records"}}`, time.Now()).AddRow("fofa", `{"asset_type":"subdomain","value":"a.example.com"}`, time.Now()))
	value, err := svc.RunActivity(context.Background(), 1, run.ID)
	require.NoError(t, err)
	require.Len(t, value.Stages, 1)
	require.Equal(t, "success", value.Stages[0].Status)
	require.Len(t, value.Recent, 1)
	require.Equal(t, "no_records", value.Recent[0].DNSStatus)
	require.Equal(t, TaskRunStatusRunning, value.Status)
	// A failed callback with attempts left is retrying, not failed.
	require.Equal(t, 1, value.FailedBatches)
	require.Equal(t, 2, value.RetryingBatches)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestEngineCompletionWaitsForStreamIngest(t *testing.T) {
	svc, run, now := runningCallbackFixture(t)
	acceptCallbackForIngest(t, svc, now, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 1)
	acceptCallbackForIngest(t, svc, now, run.ID, 2, CallbackPhaseCompleted, TaskRunStatusSuccess, 0)
	svc.engine = &fakeEngine{statuses: []EngineJobStatus{{Status: EngineJobStatusSuccess, ResultCount: 1}}}
	after, err := svc.ReconcileTaskRun(context.Background(), ReconcileTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "system"})
	require.NoError(t, err)
	require.Equal(t, TaskRunStatusRunning, after.Status)
}
