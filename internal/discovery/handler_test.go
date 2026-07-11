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
	raw := []byte(`{"run_id":1,"seq":1,"phase":"progress","status":"running","result_count":1}`)
	req := signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", now, "secret", raw)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, enqueuer.calls)

	req = signedCallbackRequest(t, http.MethodPost, "/api/v1/discovery/callback?project_id=1&run_id=1&seq=1", now, "secret", raw)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, enqueuer.calls)
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

func signedCallbackRequest(t *testing.T, method, target string, ts time.Time, secret string, raw []byte) *http.Request {
	t.Helper()
	input := signedCallbackInput(1, 1, 1, ts, secret, raw)
	req := httptest.NewRequest(method, target, bytes.NewReader(raw))
	req.Header.Set(headerCallbackTimestamp, input.Timestamp)
	req.Header.Set(headerCallbackSignature, input.Signature)
	return req
}
