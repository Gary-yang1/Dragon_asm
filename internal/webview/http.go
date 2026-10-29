package webview

import (
	"database/sql"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

// Serve is called only after the owning handler's project/action checks.
func Serve(c *gin.Context, db *sql.DB, projectID, runID uint64) {
	page, ok := httpx.BindPageQuery(c)
	if !ok {
		return
	}
	q := Query{Page: int(page.PageNumber), Size: int(page.PageSize), Keyword: c.Query("keyword"), Outcome: c.Query("outcome"), CDN: c.Query("cdn"), Cloud: c.Query("cloud"), Sort: c.Query("sort")}
	if !q.Valid() {
		httpx.BadRequest(c, "网站筛选条件无效")
		return
	}
	result, err := List(c.Request.Context(), db, projectID, runID, q)
	if err != nil {
		httpx.Internal(c)
		return
	}
	httpx.OK(c, result)
}
