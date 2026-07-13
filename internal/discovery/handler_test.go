package discovery

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandlerCallbackSuccessAndDuplicate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC()
	enqueuer := &fakeCallbackEnqueuer{}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = enqueuer
	svc.engine = &fakeEngine{ids: []string{"job-http"}}
	dispatched, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{
		ProjectID: 1,
		RunID:     run.ID,
		ActorID:   "alice",
	})
	require.NoError(t, err)

	router := gin.New()
	NewHandler(svc, "secret", nil).RegisterPublicRoutes(router.Group("/api/v1"))
	raw := validCallbackRaw(t, dispatched.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 1)
	req := signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", now, "secret", raw)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, enqueuer.calls)

	req = signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", now, "secret", raw)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 2, enqueuer.calls)
	assert.Equal(t, dispatched.ID, run.ID)
}

func TestHandlerCallbackRejectsInvalidSignature(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, _, _ := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	router := gin.New()
	NewHandler(svc, "secret", nil).RegisterPublicRoutes(router.Group("/api/v1"))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", bytes.NewReader([]byte(`{}`)))
	req.Header.Set(headerCallbackTimestamp, "1")
	req.Header.Set(headerCallbackSignature, "bad")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIdentityBoundHandlerRequiresMatchingEngineID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC()
	enqueuer := &fakeCallbackEnqueuer{}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = enqueuer
	svc.engine = &fakeEngine{ids: []string{"job-identity"}}
	run.CallbackSecretRef = "baiyan-primary"
	svc.repo.(*fakeRepo).runs[run.ProjectID][run.ID].CallbackSecretRef = run.CallbackSecretRef
	_, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "alice"})
	require.NoError(t, err)

	router := gin.New()
	handler, err := NewIdentityBoundHandler(svc, "baiyan-primary", "secret", nil)
	require.NoError(t, err)
	handler.RegisterPublicRoutes(router.Group("/api/v1"))
	raw := validCallbackRaw(t, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 0)

	req := signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", now, "secret", raw)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Zero(t, enqueuer.calls)

	req = signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", now, "secret", raw)
	req.Header.Set(headerCallbackEngineID, "baiyan-secondary")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Zero(t, enqueuer.calls)

	req = signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", now, "secret", raw)
	req.Header.Set(headerCallbackEngineID, "baiyan-primary")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, enqueuer.calls)
}

func TestIdentityBoundHandlerAllowsLegacyRunWithoutSecretRef(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC()
	enqueuer := &fakeCallbackEnqueuer{}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = enqueuer
	svc.engine = &fakeEngine{ids: []string{"job-legacy"}}
	_, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "alice"})
	require.NoError(t, err)

	router := gin.New()
	handler, err := NewIdentityBoundHandler(svc, "baiyan-primary", "secret", nil)
	require.NoError(t, err)
	handler.RegisterPublicRoutes(router.Group("/api/v1"))
	raw := validCallbackRaw(t, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	req := signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", now, "secret", raw)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, enqueuer.calls)
}

func TestCredentialBoundHandlerSupportsRotationWithoutCrossIdentityUse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC()
	enqueuer := &fakeCallbackEnqueuer{}
	svc, _, run := newDispatchPlanFixture(t, StatusActive, true, TaskRunStatusPending, dispatchConfigFor("example.com"))
	svc.nowFn = func() time.Time { return now }
	svc.callbackEnqueuer = enqueuer
	svc.engine = &fakeEngine{ids: []string{"job-rotation"}}
	run.CallbackSecretRef = "baiyan-old"
	svc.repo.(*fakeRepo).runs[run.ProjectID][run.ID].CallbackSecretRef = run.CallbackSecretRef
	_, err := svc.DispatchTaskRun(context.Background(), DispatchTaskRunInput{ProjectID: 1, RunID: run.ID, ActorID: "alice"})
	require.NoError(t, err)

	credentials, err := NewCallbackCredentialSet(
		"baiyan-new", "",
		`{"baiyan-old":"old-secret","baiyan-new":"new-secret"}`,
	)
	require.NoError(t, err)
	router := gin.New()
	handler, err := NewCredentialBoundHandler(svc, credentials, nil)
	require.NoError(t, err)
	handler.RegisterPublicRoutes(router.Group("/api/v1"))

	raw := validCallbackRaw(t, run.ID, 1, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	req := signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", now, "old-secret", raw)
	req.Header.Set(headerCallbackEngineID, "baiyan-old")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, enqueuer.calls)

	raw = validCallbackRaw(t, run.ID, 2, CallbackPhaseProgress, TaskRunStatusRunning, 0)
	req = signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=2", now, "new-secret", raw)
	req.Header.Set(headerCallbackEngineID, "baiyan-new")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, 1, enqueuer.calls)

	req = signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=2", now, "unknown-secret", raw)
	req.Header.Set(headerCallbackEngineID, "unknown")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, 1, enqueuer.calls)
}

func TestIdentityBoundHandlerRejectsInvalidConfiguration(t *testing.T) {
	svc := NewService(newFakeRepo())
	for _, engineID := range []string{"", ".hidden", "bad identity"} {
		_, err := NewIdentityBoundHandler(svc, engineID, "secret", nil)
		assert.ErrorIs(t, err, ErrInvalidCallbackIdentity)
	}
}

func TestHandlerCallbackRejectsBadQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := NewService(newFakeRepo())
	router := gin.New()
	NewHandler(svc, "secret", nil).RegisterPublicRoutes(router.Group("/api/v1"))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/callback?project_id=0&run_id=1&seq=1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlerCallbackRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := NewService(newFakeRepo())
	router := gin.New()
	NewHandler(svc, "secret", nil).RegisterPublicRoutes(router.Group("/api/v1"))
	body := bytes.Repeat([]byte("x"), callbackMaxBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), "CALLBACK_TOO_LARGE")
}

func signedCallbackRequest(t *testing.T, method, target string, ts time.Time, secret string, raw []byte) *http.Request {
	t.Helper()
	input := signedCallbackInput(1, 1, 1, ts, secret, raw)
	req := httptest.NewRequest(method, target, bytes.NewReader(raw))
	req.Header.Set(headerCallbackTimestamp, input.Timestamp)
	req.Header.Set(headerCallbackSignature, input.Signature)
	return req
}
