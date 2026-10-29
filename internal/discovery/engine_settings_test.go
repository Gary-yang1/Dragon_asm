package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

func settingsTestStore(t *testing.T) (*EngineSettingsStore, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	store, err := NewEngineSettingsStore(db, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	return store, mock
}
func settingsFixture() EngineSettings {
	return EngineSettings{PassiveURL: "https://engine.example.test", PassiveToken: "private-test-token", Policy: DefaultActiveDispatchPolicy()}
}
func TestEngineSettingsEncryptionAndView(t *testing.T) {
	store, _ := settingsTestStore(t)
	c := settingsFixture()
	sealed, err := store.seal(4, c)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), c.PassiveToken)
	opened, err := store.open(4, sealed)
	require.NoError(t, err)
	require.Equal(t, c, opened)
	_, err = store.open(5, sealed)
	require.ErrorIs(t, err, ErrEngineSettingsUnavailable)
	sealed[len(sealed)-1] ^= 1
	_, err = store.open(4, sealed)
	require.ErrorIs(t, err, ErrEngineSettingsUnavailable)
	view, _ := json.Marshal(settingsView(EngineSettingsSnapshot{Version: 4, Settings: c}))
	require.NotContains(t, string(view), c.PassiveToken)
	require.NotContains(t, string(view), `"passive_token":"private`)
}
func TestEngineSettingsKeyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{1}, 32), 0644))
	_, err := LoadEngineSettingsKey(path)
	require.Error(t, err)
	require.NoError(t, os.Chmod(path, 0600))
	key, err := LoadEngineSettingsKey(path)
	require.NoError(t, err)
	require.Len(t, key, 32)
}
func TestEngineSettingsSaveConflictAndAuditRollback(t *testing.T) {
	store, mock := settingsTestStore(t)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT version FROM engine_settings_head").WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(2))
	mock.ExpectRollback()
	_, err := store.Save(context.Background(), 1, settingsFixture(), audit.Event{ActorID: "1"})
	require.ErrorIs(t, err, ErrEngineSettingsConflict)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT version FROM engine_settings_head").WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(2))
	mock.ExpectExec("INSERT INTO engine_settings_version").WithArgs(uint64(3), sqlmock.AnyArg(), "1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE engine_settings_head").WithArgs(uint64(3)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO audit_log").WillReturnError(errors.New("audit unavailable"))
	mock.ExpectRollback()
	_, err = store.Save(context.Background(), 2, settingsFixture(), audit.Event{ActorID: "1"})
	require.ErrorIs(t, err, ErrEngineSettingsUnavailable)
	require.NoError(t, mock.ExpectationsWereMet())
}
func TestEngineSettingsPinsOldRunsWhileNewWorkUsesLatest(t *testing.T) {
	store, mock := settingsTestStore(t)
	old := settingsFixture()
	next := old
	next.PassiveURL = "https://new-engine.example.test"
	next.PassiveToken = "different-token"
	a, err := store.seal(1, old)
	require.NoError(t, err)
	b, err := store.seal(2, next)
	require.NoError(t, err)
	mock.ExpectQuery("SELECT version FROM engine_settings_head").WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(2))
	mock.ExpectQuery("SELECT version, encrypted_payload").WithArgs(uint64(2)).WillReturnRows(sqlmock.NewRows([]string{"version", "encrypted_payload", "created_by", "created_at"}).AddRow(2, b, "1", time.Now()))
	svc := NewService(nil, WithEngineSettings(store))
	current, err := svc.withLatestSettings(context.Background())
	require.NoError(t, err)
	adapter, err := current.engineForTaskType(TaskTypeDNS)
	require.NoError(t, err)
	require.Equal(t, next.PassiveURL, adapter.(*HTTPEngineAdapter).baseURL)
	mock.ExpectQuery("SELECT version FROM engine_run_settings").WithArgs(uint64(9), uint64(81)).WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(1))
	mock.ExpectQuery("SELECT version, encrypted_payload").WithArgs(uint64(1)).WillReturnRows(sqlmock.NewRows([]string{"version", "encrypted_payload", "created_by", "created_at"}).AddRow(1, a, "system", time.Now()))
	pinned, err := svc.withRunSettings(context.Background(), 9, 81)
	require.NoError(t, err)
	adapter, err = pinned.engineForTaskType(TaskTypeDNS)
	require.NoError(t, err)
	require.Equal(t, old.PassiveURL, adapter.(*HTTPEngineAdapter).baseURL)
	require.Equal(t, uint64(1), pinned.engineConfigVersion)
	require.NoError(t, mock.ExpectationsWereMet())
}
func TestEngineSettingsPatchRetainsSecretsAndRejectsUnsafeURLs(t *testing.T) {
	c := settingsFixture()
	updated, err := applySettingsPatch(c, UpdateEngineSettingsInput{Values: map[string]string{"passive_token": "", "passive_url": "https://new.example.test"}})
	require.NoError(t, err)
	require.Equal(t, c.PassiveToken, updated.PassiveToken)
	for _, value := range []string{"http://169.254.169.254", "http://100.100.100.200", "http://127.0.0.1", "http://[fd00:ec2::254]", "http://user:password@example.test", "https://example.test?secret=x"} {
		require.Error(t, validateManagedURL(value), value)
	}
	require.NoError(t, validateManagedURL("http://192.168.10.20:9090"))
	_, err = applySettingsPatch(c, UpdateEngineSettingsInput{Values: map[string]string{"unexpected": "value"}})
	require.ErrorIs(t, err, ErrEngineSettingsInvalid)
}
func TestEngineSettingsModificationRequiresPlatformAdministrator(t *testing.T) {
	svc, _, _, _ := newEngineManagementTestService()
	svc.users = engineManagementUserFake{user: nil}
	_, err := svc.UpdateConfiguration(context.Background(), "1", UpdateEngineSettingsInput{}, AuditMeta{})
	require.ErrorIs(t, err, ErrEngineManagementForbidden)
}
func TestEngineManagementListNeverCallsInspectors(t *testing.T) {
	svc, passive, active, _ := newEngineManagementTestService()
	result, err := svc.List(context.Background(), "1")
	require.NoError(t, err)
	require.Zero(t, passive.calls.Load())
	require.Zero(t, active.calls.Load())
	require.Equal(t, EngineHealthUnknown, result.Items[0].Health)
	_, err = svc.Check(context.Background(), "1", EngineRoutePassive, AuditMeta{})
	require.NoError(t, err)
	result, err = svc.List(context.Background(), "1")
	require.NoError(t, err)
	require.Equal(t, int32(1), passive.calls.Load())
	require.Zero(t, active.calls.Load())
	require.Equal(t, EngineHealthHealthy, result.Items[0].Health)
}

func TestManagedDispatchProvisionsVersionWithoutEmbeddingSecretsInJob(t *testing.T) {
	var calls []string
	client := fakeHTTPClient{do: func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		if r.Method == http.MethodPut {
			require.Contains(t, string(body), "provider-secret")
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"version":12}`))}, nil
		}
		require.NotContains(t, string(body), "provider-secret")
		var request dispatchRequest
		require.NoError(t, json.Unmarshal(body, &request))
		require.Equal(t, uint64(12), request.ConfigurationVersion)
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"engine_job_id":"job-7"}`))}, nil
	}}
	adapter, err := NewHTTPEngineAdapter("https://engine.example.test", "connection-token", client)
	require.NoError(t, err)
	adapter.configurationVersion = 12
	adapter.providerSettings = &ProviderSettings{FOFAKey: "provider-secret"}
	_, err = adapter.Dispatch(context.Background(), ScanJob{RunID: 7, ProjectID: 2, ScopeID: 3, JobType: TaskTypeDNS, Targets: []Target{{Type: TargetTypeDomain, Value: "example.com"}}, CallbackURL: "https://asm.example.test/callback"})
	require.NoError(t, err)
	require.Equal(t, []string{"PUT /management/configurations/12", "POST /scan"}, calls)
}
