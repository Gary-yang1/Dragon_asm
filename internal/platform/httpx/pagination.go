package httpx

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Pagination defaults and hard limits shared by every paginated list endpoint.
const (
	DefaultPageNumber = 1
	DefaultPageSize   = 20
	MaxPageSize       = 100
)

// PageQuery holds validated offset/limit pagination parameters parsed from the
// request query string.
// PageQuery fields carry snake_case JSON tags so that, even if a handler
// mistakenly returns a PageQuery directly, it serializes consistently with the
// PageData contract rather than as PascalCase. Prefer returning PageData[T] for
// real list endpoints.
type PageQuery struct {
	PageNumber int `json:"page_number"`
	PageSize   int `json:"page_size"`
}

// Offset returns the zero-based row offset (for SQL OFFSET / cursor math).
func (p PageQuery) Offset() int { return (p.PageNumber - 1) * p.PageSize }

// Limit returns the row count to fetch (for SQL LIMIT).
func (p PageQuery) Limit() int { return p.PageSize }

// ParsePageQuery parses and validates page_number / page_size from a query map.
// It is a pure function (no gin dependency) so it can be unit-tested directly.
//
// Rules:
//   - Missing or empty params take the defaults (page_number=1, page_size=20).
//   - Both params must be base-10 integers.
//   - page_number < 1 and page_size < 1 are rejected.
//   - page_size > MaxPageSize is rejected — it is never silently clamped.
//
// The returned error message is safe to surface to the caller as a 400 detail.
func ParsePageQuery(q url.Values) (PageQuery, error) {
	pq := PageQuery{
		PageNumber: DefaultPageNumber,
		PageSize:   DefaultPageSize,
	}

	if raw := q.Get("page_number"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return PageQuery{}, fmt.Errorf("page_number must be an integer, got %q", raw)
		}
		if n < 1 {
			return PageQuery{}, fmt.Errorf("page_number must be >= 1, got %d", n)
		}
		pq.PageNumber = n
	}

	if raw := q.Get("page_size"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return PageQuery{}, fmt.Errorf("page_size must be an integer, got %q", raw)
		}
		if n < 1 {
			return PageQuery{}, fmt.Errorf("page_size must be >= 1, got %d", n)
		}
		if n > MaxPageSize {
			// Reject explicitly: silent truncation would hide caller bugs.
			return PageQuery{}, fmt.Errorf("page_size must be <= %d, got %d", MaxPageSize, n)
		}
		pq.PageSize = n
	}

	return pq, nil
}

// BindPageQuery parses and validates pagination params from the request query
// string. On validation failure it writes a 400 BAD_REQUEST response (carrying
// the request_id) and returns ok=false so the handler can return early:
//
//	pq, ok := httpx.BindPageQuery(c)
//	if !ok {
//	    return
//	}
func BindPageQuery(c *gin.Context) (PageQuery, bool) {
	pq, err := ParsePageQuery(c.Request.URL.Query())
	if err != nil {
		BadRequest(c, err.Error())
		return PageQuery{}, false
	}
	return pq, true
}
