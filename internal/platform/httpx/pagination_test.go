package httpx_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

func TestParsePageQueryDefaults(t *testing.T) {
	// No params at all.
	pq, err := httpx.ParsePageQuery(url.Values{})
	require.NoError(t, err)
	assert.Equal(t, httpx.DefaultPageNumber, pq.PageNumber)
	assert.Equal(t, httpx.DefaultPageSize, pq.PageSize)

	// Empty values are treated as "not provided" -> defaults.
	pq, err = httpx.ParsePageQuery(url.Values{"page_number": {""}, "page_size": {""}})
	require.NoError(t, err)
	assert.Equal(t, httpx.DefaultPageNumber, pq.PageNumber)
	assert.Equal(t, httpx.DefaultPageSize, pq.PageSize)
}

func TestParsePageQueryValid(t *testing.T) {
	cases := []struct {
		q          url.Values
		wantNumber int
		wantSize   int
	}{
		{url.Values{"page_number": {"2"}}, 2, httpx.DefaultPageSize},
		{url.Values{"page_size": {"50"}}, httpx.DefaultPageNumber, 50},
		{url.Values{"page_number": {"3"}, "page_size": {"100"}}, 3, 100}, // boundary max
		{url.Values{"page_size": {"1"}}, httpx.DefaultPageNumber, 1},     // boundary min
	}
	for _, tc := range cases {
		pq, err := httpx.ParsePageQuery(tc.q)
		require.NoErrorf(t, err, "input: %v", tc.q)
		assert.Equalf(t, tc.wantNumber, pq.PageNumber, "input: %v", tc.q)
		assert.Equalf(t, tc.wantSize, pq.PageSize, "input: %v", tc.q)
	}
}

func TestParsePageQueryInvalid(t *testing.T) {
	cases := []url.Values{
		{"page_number": {"0"}},   // < 1
		{"page_number": {"-1"}},  // < 1
		{"page_number": {"abc"}}, // non-integer
		{"page_number": {"1.5"}}, // non-integer
		{"page_size": {"0"}},     // < 1
		{"page_size": {"-5"}},    // < 1
		{"page_size": {"101"}},   // > max
		{"page_size": {"1000"}},  // > max
		{"page_size": {"abc"}},   // non-integer
	}
	for _, q := range cases {
		_, err := httpx.ParsePageQuery(q)
		require.Errorf(t, err, "expected rejection for input %v", q)
	}
}

func TestPageQueryOffsetLimit(t *testing.T) {
	cases := []struct {
		pq         httpx.PageQuery
		wantOffset int
		wantLimit  int
	}{
		{httpx.PageQuery{PageNumber: 1, PageSize: 20}, 0, 20},
		{httpx.PageQuery{PageNumber: 2, PageSize: 20}, 20, 20},
		{httpx.PageQuery{PageNumber: 3, PageSize: 50}, 100, 50},
	}
	for _, tc := range cases {
		assert.Equalf(t, tc.wantOffset, tc.pq.Offset(), "input: %+v", tc.pq)
		assert.Equalf(t, tc.wantLimit, tc.pq.Limit(), "input: %+v", tc.pq)
	}
}

// TestBindPageQueryHTTP drives the full gin middleware + helper path with a
// throwaway /example handler to prove the 400 wiring, request_id propagation,
// and default behavior end-to-end.
func TestBindPageQueryHTTP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	engine := httpx.NewEngine(logger)

	engine.GET("/example", func(c *gin.Context) {
		pq, ok := httpx.BindPageQuery(c)
		if !ok {
			return
		}
		httpx.OK(c, pq)
	})

	t.Run("no params use defaults and echo request_id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/example", nil)
		engine.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		var body struct {
			RequestID string `json:"request_id"`
			Data      struct {
				PageNumber int `json:"page_number"`
				PageSize   int `json:"page_size"`
			} `json:"data"`
		}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, httpx.DefaultPageNumber, body.Data.PageNumber)
		assert.Equal(t, httpx.DefaultPageSize, body.Data.PageSize)
		assert.NotEmpty(t, body.RequestID, "success response must carry request_id")
		assert.Equal(t, body.RequestID, w.Header().Get("X-Request-ID"))
	})

	t.Run("explicit valid values", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/example?page_number=4&page_size=25", nil)
		engine.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		var body struct {
			Data struct {
				PageNumber int `json:"page_number"`
				PageSize   int `json:"page_size"`
			} `json:"data"`
		}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, 4, body.Data.PageNumber)
		assert.Equal(t, 25, body.Data.PageSize)
	})

	t.Run("page_size over max returns 400 without clamping", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/example?page_size=101", nil)
		engine.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		var body httpx.ErrorResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		assert.Equal(t, httpx.ErrCodeBadRequest, body.Error.Code)
		assert.NotEmpty(t, body.Error.Message)
		assert.NotEmpty(t, body.RequestID, "error response must carry request_id")
		assert.Equal(t, body.RequestID, w.Header().Get("X-Request-ID"))
	})

	t.Run("invalid page_number returns 400", func(t *testing.T) {
		for _, raw := range []string{"0", "-1", "abc"} {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/example?page_number="+raw, nil)
			engine.ServeHTTP(w, req)
			require.Equalf(t, http.StatusBadRequest, w.Code, "page_number=%s", raw)
		}
	})

	t.Run("invalid page_size returns 400", func(t *testing.T) {
		for _, raw := range []string{"0", "-1", "101", "abc"} {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/example?page_size="+raw, nil)
			engine.ServeHTTP(w, req)
			require.Equalf(t, http.StatusBadRequest, w.Code, "page_size=%s", raw)
		}
	})
}
