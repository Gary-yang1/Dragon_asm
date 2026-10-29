package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

type engineManagementUserFake struct {
	user *auth.User
	role string
	err  error
}

func (f engineManagementUserFake) GetByID(_ context.Context, id uint64) (*auth.User, error) {
	if f.err != nil || f.user == nil || f.user.ID != id {
		return nil, f.err
	}
	copy := *f.user
	return &copy, nil
}

func (f engineManagementUserFake) GetGlobalRole(context.Context, uint64) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.role, nil
}

type passiveInspectorFake struct {
	status PassiveEngineManagementStatus
	err    error
	calls  atomic.Int32
}

func (f *passiveInspectorFake) CheckManagementStatus(context.Context) (PassiveEngineManagementStatus, error) {
	f.calls.Add(1)
	return f.status, f.err
}

type activeInspectorFake struct {
	status ActiveEngineReadiness
	err    error
	calls  atomic.Int32
}

func (f *activeInspectorFake) CheckReadiness(context.Context) (ActiveEngineReadiness, error) {
	f.calls.Add(1)
	return f.status, f.err
}

type workerStatusReaderFake struct {
	status WorkerEngineRuntimeStatus
	err    error
}

func (f workerStatusReaderFake) ReadWorkerEngineStatus(context.Context) (WorkerEngineRuntimeStatus, error) {
	return f.status, f.err
}

type engineManagementAuditFake struct {
	events []audit.Event
	err    error
}

func (f *engineManagementAuditFake) Record(_ context.Context, event audit.Event) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}

func newEngineManagementTestService() (*EngineManagementService, *passiveInspectorFake, *activeInspectorFake, *engineManagementAuditFake) {
	config := EngineRouterConfig{
		PassiveBaseURL:   "https://baiyan.example.test",
		PassiveToken:     "passive-token-secret",
		ActiveBaseURL:    "https://active.example.test",
		ActiveAccessKey:  "active-access-key",
		ActiveSecretKey:  "active-secret-key",
		ActiveProjectMap: `{"2":22,"1":11}`,
	}
	policy := ActiveDispatchPolicy{Enabled: true, RequireApproval: false, RequireOwnership: false}
	passive := &passiveInspectorFake{status: PassiveEngineManagementStatus{
		Status: "ready", EngineID: "baiyan-primary", Capabilities: []string{TaskTypeDNS, TaskTypePassiveIntel},
		Providers: []PassiveEngineProviderStatus{{
			Key: "fofa", Name: "FOFA", Configured: true,
			Credentials: []PassiveEngineCredentialStatus{
				{Key: "email", Configured: true, MaskedValue: "u********r@example.test"},
				{Key: "key", Configured: true, MaskedValue: "••••••••abcd"},
			},
		}},
	}}
	active := &activeInspectorFake{status: ActiveEngineReadiness{OnlineNodes: []ActiveEngineNode{{
		NodeID: "node-1", Capabilities: []string{TaskTypePortProbe, TaskTypeWebProbe},
	}}}}
	audits := &engineManagementAuditFake{}
	now := time.Date(2026, time.August, 3, 8, 0, 0, 0, time.UTC)
	service := &EngineManagementService{
		checks: &engineCheckCache{items: make(map[string]ManagedEngineSummary)},
		config: config,
		configStatus: EngineRouterConfigStatus{
			Passive: EngineRouteConfigStatus{Configured: true, Ready: true},
			Active:  EngineRouteConfigStatus{Configured: true, Ready: true},
		},
		policy: policy,
		users: engineManagementUserFake{user: &auth.User{
			ID: 1, TenantID: "tenant-1", OrgID: "org-1", Status: auth.UserStatusActive,
		}, role: asmcasbin.RoleSystemAdmin},
		audit: audits, passive: passive, active: active,
		worker: workerStatusReaderFake{status: WorkerEngineRuntimeStatus{
			ConfigFingerprint: EngineRuntimeConfigFingerprint(config, policy), UpdatedAt: now.Add(-10 * time.Second),
		}},
		now: func() time.Time { return now }, timeout: time.Second,
	}
	return service, passive, active, audits
}

func TestEngineManagementListMasksAllCredentialsAndReportsHealth(t *testing.T) {
	service, passive, active, _ := newEngineManagementTestService()
	_, err := service.Check(context.Background(), "1", EngineRoutePassive, AuditMeta{})
	require.NoError(t, err)
	_, err = service.Check(context.Background(), "1", EngineRouteActive, AuditMeta{})
	require.NoError(t, err)

	overview, err := service.List(context.Background(), "1")
	require.NoError(t, err)
	require.Len(t, overview.Items, 2)
	assert.Equal(t, int32(1), passive.calls.Load())
	assert.Equal(t, int32(1), active.calls.Load())
	assert.Equal(t, WorkerEngineStatusOnline, overview.Worker.Status)
	require.NotNil(t, overview.Worker.ConfigMatches)
	assert.True(t, *overview.Worker.ConfigMatches)

	passiveSummary := overview.Items[0]
	assert.Equal(t, EngineRoutePassive, passiveSummary.Route)
	assert.Equal(t, EngineHealthHealthy, passiveSummary.Health)
	require.Len(t, passiveSummary.Providers, 1)
	assert.Equal(t, "FOFA Email", passiveSummary.Providers[0].Credentials[0].Label)
	assert.Equal(t, "FOFA Key", passiveSummary.Providers[0].Credentials[1].Label)
	assert.Equal(t, "••••••••abcd", passiveSummary.Providers[0].Credentials[1].MaskedValue)

	activeSummary := overview.Items[1]
	assert.Equal(t, EngineRouteActive, activeSummary.Route)
	assert.Equal(t, EngineHealthHealthy, activeSummary.Health)
	assert.Equal(t, 2, activeSummary.ProjectMapSize)
	require.Len(t, activeSummary.Nodes, 1)
	assert.Contains(t, activeSummary.Credentials[0].MaskedValue, "•")
	assert.Contains(t, activeSummary.Credentials[1].MaskedValue, "•")

	payload, err := json.Marshal(overview)
	require.NoError(t, err)
	encoded := string(payload)
	for _, rawSecret := range []string{"passive-token-secret", "active-access-key", "active-secret-key"} {
		assert.NotContains(t, encoded, rawSecret)
	}
}

func TestEngineManagementListRejectsNonAdminWithoutProbing(t *testing.T) {
	service, passive, active, _ := newEngineManagementTestService()
	service.users = engineManagementUserFake{user: &auth.User{ID: 1, Status: auth.UserStatusActive}, role: asmcasbin.RoleSecurityAdmin}

	_, err := service.List(context.Background(), "1")
	assert.ErrorIs(t, err, ErrEngineManagementForbidden)
	assert.Zero(t, passive.calls.Load())
	assert.Zero(t, active.calls.Load())
}

func TestEngineManagementCheckAuditsSuccessAndFailureWithoutSecrets(t *testing.T) {
	service, _, active, audits := newEngineManagementTestService()
	meta := AuditMeta{IP: "192.0.2.1", UserAgent: "test-agent", RequestID: "request-1"}

	result, err := service.Check(context.Background(), "1", EngineRoutePassive, meta)
	require.NoError(t, err)
	assert.Equal(t, EngineHealthHealthy, result.Health)
	require.Len(t, audits.events, 1)
	assert.Equal(t, audit.ResultSuccess, audits.events[0].Result)

	active.err = errors.New("upstream unavailable")
	result, err = service.Check(context.Background(), "1", EngineRouteActive, meta)
	require.NoError(t, err)
	assert.Equal(t, EngineHealthUnreachable, result.Health)
	require.Len(t, audits.events, 2)
	assert.Equal(t, audit.ResultFailure, audits.events[1].Result)
	assert.Equal(t, "ENGINE_NOT_READY", audits.events[1].ErrorCode)

	auditPayload, err := json.Marshal(audits.events)
	require.NoError(t, err)
	encoded := string(auditPayload)
	for _, forbidden := range []string{
		"passive-token-secret", "active-access-key", "active-secret-key",
		"baiyan.example.test", "active.example.test", "upstream unavailable",
	} {
		assert.NotContains(t, encoded, forbidden)
	}

	_, err = service.Check(context.Background(), "1", EngineRoute("invalid"), meta)
	assert.ErrorIs(t, err, ErrEngineManagementInvalidRoute)
	assert.Len(t, audits.events, 2)
}

func TestEngineManagementRejectsUnmaskedProviderValue(t *testing.T) {
	service, passive, _, _ := newEngineManagementTestService()
	passive.status.Providers[0].Credentials[1].MaskedValue = "raw*provider-key"
	_, checkErr := service.Check(context.Background(), "1", EngineRoutePassive, AuditMeta{})
	require.NoError(t, checkErr)

	overview, err := service.List(context.Background(), "1")
	require.NoError(t, err)
	assert.Empty(t, overview.Items[0].Providers[0].Credentials[1].MaskedValue)
	payload, err := json.Marshal(overview)
	require.NoError(t, err)
	assert.NotContains(t, string(payload), "raw*provider-key")
}

func TestEngineManagementMasksShortAndLongCredentials(t *testing.T) {
	assert.Equal(t, maskedSecretPrefix, MaskEngineSecret("short"))
	assert.Equal(t, maskedSecretPrefix+"cdef", MaskEngineSecret("abcdefghijklmnopabcdef"))
	assert.Equal(t, maskedSecretPrefix, MaskEngineIdentifier("short"))
	assert.Equal(t, "abcd••••cdef", MaskEngineIdentifier("abcdefghijklmnopabcdef"))
}

func TestEngineRuntimeConfigFingerprintUsesRoutingAndCredentialPresenceOnly(t *testing.T) {
	policy := ActiveDispatchPolicy{Enabled: true, RequireApproval: true, RequireOwnership: false}
	base := EngineRouterConfig{
		PassiveBaseURL: "https://baiyan.example.test/", PassiveToken: "token-one",
		ActiveBaseURL: "https://active.example.test", ActiveAccessKey: "ak-one", ActiveSecretKey: "sk-one",
		ActiveProjectMap: `{"2":22,"1":11}`,
	}
	fingerprint := EngineRuntimeConfigFingerprint(base, policy)
	assert.Len(t, fingerprint, 64)
	for _, rawSecret := range []string{"token-one", "ak-one", "sk-one"} {
		assert.NotContains(t, fingerprint, rawSecret)
	}
	serializedConfig, err := json.Marshal(base)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(serializedConfig))

	differentValues := base
	differentValues.PassiveToken = "completely-different-token"
	differentValues.ActiveAccessKey = "completely-different-ak"
	differentValues.ActiveSecretKey = "completely-different-sk"
	assert.Equal(t, fingerprint, EngineRuntimeConfigFingerprint(differentValues, policy))

	reorderedMap := base
	reorderedMap.ActiveProjectMap = `{"1":11,"2":22}`
	assert.Equal(t, fingerprint, EngineRuntimeConfigFingerprint(reorderedMap, policy))

	changedRoute := base
	changedRoute.ActiveBaseURL = "https://other-active.example.test"
	assert.NotEqual(t, fingerprint, EngineRuntimeConfigFingerprint(changedRoute, policy))
	changedMapping := base
	changedMapping.ActiveProjectMap = `{"1":11,"2":23}`
	assert.NotEqual(t, fingerprint, EngineRuntimeConfigFingerprint(changedMapping, policy))
	changedPresence := base
	changedPresence.ActiveSecretKey = ""
	assert.NotEqual(t, fingerprint, EngineRuntimeConfigFingerprint(changedPresence, policy))
	changedPolicy := policy
	changedPolicy.RequireOwnership = true
	assert.NotEqual(t, fingerprint, EngineRuntimeConfigFingerprint(base, changedPolicy))
}

func TestEngineManagementWorkerSummaryReportsMismatchAndStale(t *testing.T) {
	service, _, _, _ := newEngineManagementTestService()
	now := service.now().UTC()
	service.worker = workerStatusReaderFake{status: WorkerEngineRuntimeStatus{
		ConfigFingerprint: strings.Repeat("a", 64), UpdatedAt: now.Add(-WorkerEngineHeartbeatTTL - time.Second),
	}}

	overview, err := service.List(context.Background(), "1")
	require.NoError(t, err)
	assert.Equal(t, WorkerEngineStatusStale, overview.Worker.Status)
	require.NotNil(t, overview.Worker.ConfigMatches)
	assert.False(t, *overview.Worker.ConfigMatches)

	service.worker = workerStatusReaderFake{status: WorkerEngineRuntimeStatus{
		ConfigFingerprint: EngineRuntimeConfigFingerprint(service.config, service.policy),
		UpdatedAt:         now.Add(31 * time.Second),
	}}
	overview, err = service.List(context.Background(), "1")
	require.NoError(t, err)
	assert.Equal(t, WorkerEngineStatusUnknown, overview.Worker.Status)
	assert.Nil(t, overview.Worker.ConfigMatches)
}

func TestEngineManagementHandlerUsesSnakeCaseEnvelopeAndNoStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, _, _, _ := newEngineManagementTestService()
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		c.Set(auth.CtxUserID, "1")
		c.Next()
	})
	NewEngineManagementHandler(service).RegisterRoutes(api)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/platform/discovery-engines", nil))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	assert.Contains(t, response.Body.String(), `"active_policy":{"enabled":true,"require_approval":false,"require_ownership":false}`)
	for _, rawSecret := range []string{"passive-token-secret", "active-access-key", "active-secret-key"} {
		assert.NotContains(t, response.Body.String(), rawSecret)
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/platform/discovery-engines/invalid/check", nil))
	require.Equal(t, http.StatusUnprocessableEntity, response.Code, response.Body.String())
	assert.Contains(t, response.Body.String(), `"code":"UNPROCESSABLE_ENTITY"`)
}

func TestEngineManagementHandlerReturnsForbiddenForNonAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, passive, active, _ := newEngineManagementTestService()
	service.users = engineManagementUserFake{
		user: &auth.User{ID: 1, Status: auth.UserStatusActive}, role: asmcasbin.RoleSecurityAdmin,
	}
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		c.Set(auth.CtxUserID, "1")
		c.Next()
	})
	NewEngineManagementHandler(service).RegisterRoutes(api)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/platform/discovery-engines", nil))
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	assert.Contains(t, response.Body.String(), `"code":"FORBIDDEN"`)
	assert.Zero(t, passive.calls.Load())
	assert.Zero(t, active.calls.Load())
}
