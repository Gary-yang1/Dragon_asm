package webview

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

var ErrQuery = errors.New("invalid website filter")

type Query struct {
	Page, Size                   int
	Keyword, Outcome, CDN, Cloud string
	// Sort is "" or SortValue (default) or SortRecent.
	Sort string
}

const (
	// SortValue lists the sites worth looking at first: titled responses, then
	// error pages, then untitled responses, then sites with no reported status.
	SortValue = "value"
	// SortRecent is newest observation first. Within one run every site shares
	// the same timestamp, so on its own it degrades to insertion order.
	SortRecent = "recent"
)

func (q Query) Valid() bool {
	if q.Page < 1 || q.Page > 100000 || q.Size < 1 || q.Size > 100 || len(q.Keyword) > 256 {
		return false
	}
	switch q.Outcome {
	case "", "responded", "unknown", "timeout", "dns_error", "network_error", "tls_error", "cancelled":
	default:
		return false
	}
	switch q.Sort {
	case "", SortValue, SortRecent:
	default:
		return false
	}
	for _, v := range []string{q.CDN, q.Cloud} {
		if v != "" && v != "identified" && v != "unknown" {
			return false
		}
	}
	return true
}

// List uses immutable per-run evidence, or the newest observation per website.
// Only the selected page is decoded; filtering/counting happen in the database.
func List(ctx context.Context, db *sql.DB, projectID, runID uint64, q Query) (Page, error) {
	out := Page{Items: []Website{}, PageNumber: q.Page, PageSize: q.Size}
	if !q.Valid() || projectID == 0 {
		return out, ErrQuery
	}
	if db == nil {
		return out, errors.New("website store unavailable")
	}
	// A live probe outranks a search-engine crawl of the same URL however old
	// either is; crawls only fill in sites nothing has probed. The info row that
	// lends a title prefers a real status code, then any captured title.
	const cte = `WITH candidates AS (
 SELECT o.id,o.run_id,o.observed_at,o.normalized_json AS data,SHA2(CAST(o.normalized_json AS CHAR),256) AS source_hash,o.provider,o.active_probe,
 JSON_UNQUOTE(JSON_EXTRACT(o.normalized_json,'$.url')) AS url,
 JSON_UNQUOTE(JSON_EXTRACT(o.normalized_json,'$.parent.natural_key')) AS asset_key,
 ROW_NUMBER() OVER(PARTITION BY JSON_UNQUOTE(JSON_EXTRACT(o.normalized_json,'$.url')) ORDER BY o.active_probe DESC,o.observed_at DESC,o.id DESC) AS rn,
 ROW_NUMBER() OVER(PARTITION BY JSON_UNQUOTE(JSON_EXTRACT(o.normalized_json,'$.url')) ORDER BY (JSON_UNQUOTE(JSON_EXTRACT(o.normalized_json,'$.value')) REGEXP '^[1-5][0-9][0-9]$') DESC,
 (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(o.normalized_json,'$.name')),'') NOT IN ('',JSON_UNQUOTE(JSON_EXTRACT(o.normalized_json,'$.url')))) DESC,o.active_probe DESC,o.observed_at DESC,o.id DESC) AS info_rn
 FROM discovery_observation o WHERE o.project_id=? AND (?=0 OR o.run_id=?) AND o.kind='exposure'
 AND o.deleted_at='1970-01-01 00:00:00' AND JSON_UNQUOTE(JSON_EXTRACT(o.normalized_json,'$.exposure_type'))='web'
 ), websites AS (
 SELECT c.id,c.run_id,c.observed_at,
 CASE WHEN info.id IS NULL THEN c.data ELSE JSON_SET(c.data,'$.name',JSON_EXTRACT(info.data,'$.name'),'$.fingerprint',JSON_EXTRACT(info.data,'$.fingerprint')) END AS data,
 c.url,COALESCE(a.id,0) AS asset_id,COALESCE(info.run_id,c.run_id) AS info_run_id,info.observed_at AS info_observed_at,c.source_hash,c.provider,c.active_probe FROM candidates c
 LEFT JOIN candidates info ON info.url=c.url AND info.info_rn=1 AND ?=0 AND info.id<>c.id
 AND JSON_UNQUOTE(JSON_EXTRACT(c.data,'$.value')) NOT REGEXP '^[1-5][0-9][0-9]$'
 AND (JSON_UNQUOTE(JSON_EXTRACT(info.data,'$.value')) REGEXP '^[1-5][0-9][0-9]$'
  OR COALESCE(JSON_UNQUOTE(JSON_EXTRACT(info.data,'$.name')),'') NOT IN ('',info.url))
 LEFT JOIN asset a ON a.project_id=? AND a.asset_key=c.asset_key AND a.deleted_at='1970-01-01 00:00:00'
 WHERE c.rn=1 AND (?<>0 OR a.id IS NOT NULL)
 UNION ALL
 SELECT 0,0,a.last_seen,JSON_OBJECT('url',a.value,'name','','value','unknown','fingerprint',''),a.value,a.id,0,NULL,'','',FALSE FROM asset a
 WHERE a.project_id=? AND ?=0 AND a.asset_type='web' AND a.deleted_at='1970-01-01 00:00:00'
 AND NOT EXISTS(SELECT 1 FROM candidates c WHERE c.asset_key=a.asset_key)
 ), networked AS (
 SELECT w.*,CASE WHEN e.source_hash<>w.source_hash THEN 'failed' ELSE COALESCE(e.state,'not_started') END AS enrichment_state,
 CASE WHEN e.source_hash<>w.source_hash THEN '网站来源记录已更新，原网络归属不再适用，请重试网络查询' ELSE COALESCE(e.error_summary,'') END AS enrichment_error,
 CASE WHEN e.source_hash=w.source_hash AND e.state='complete' AND JSON_UNQUOTE(JSON_EXTRACT(e.result_json,'$.status')) IN ('success','partial') THEN e.result_json ELSE NULL END AS network_data
 FROM websites w LEFT JOIN web_network_enrichment e ON e.observation_id=w.id AND e.project_id=? AND e.run_id=w.run_id
 ), formatted AS (
 SELECT w.*,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(data,'$.web_observation.outcome')),
 CASE WHEN JSON_UNQUOTE(JSON_EXTRACT(data,'$.value')) REGEXP '^[1-5][0-9][0-9]$' THEN 'responded' ELSE 'unknown' END) AS outcome,
 COALESCE(JSON_UNQUOTE(JSON_EXTRACT(COALESCE(network_data,JSON_EXTRACT(data,'$.web_observation')),'$.cdn.status')),'unknown') AS cdn,
 COALESCE(JSON_UNQUOTE(JSON_EXTRACT(COALESCE(network_data,JSON_EXTRACT(data,'$.web_observation')),'$.cloud.status')),'unknown') AS cloud
 FROM networked w
 ), filtered AS (
 SELECT * FROM formatted f WHERE (?='' OR LOCATE(LOWER(?),LOWER(CONCAT_WS(' ',url,
 JSON_UNQUOTE(JSON_EXTRACT(data,'$.name')),JSON_UNQUOTE(JSON_EXTRACT(data,'$.fingerprint')),
 JSON_EXTRACT(COALESCE(network_data,JSON_EXTRACT(data,'$.web_observation')),'$.resolved_ips'),
 JSON_EXTRACT(COALESCE(network_data,JSON_EXTRACT(data,'$.web_observation')),'$.cname_chain'),
 JSON_UNQUOTE(JSON_EXTRACT(COALESCE(network_data,JSON_EXTRACT(data,'$.web_observation')),'$.cdn.provider')),
 JSON_UNQUOTE(JSON_EXTRACT(COALESCE(network_data,JSON_EXTRACT(data,'$.web_observation')),'$.cloud.provider')),
 JSON_UNQUOTE(JSON_EXTRACT(data,'$.web_observation.connected_ip')))))>0
 OR EXISTS(SELECT 1 FROM discovery_observation s WHERE s.project_id=? AND s.run_id=f.info_run_id AND s.kind='exposure'
 AND s.deleted_at='1970-01-01 00:00:00' AND JSON_UNQUOTE(JSON_EXTRACT(s.normalized_json,'$.exposure_type'))='service'
 AND JSON_UNQUOTE(JSON_EXTRACT(s.normalized_json,'$.url'))=f.url
 AND LOCATE(LOWER(?),LOWER(JSON_UNQUOTE(JSON_EXTRACT(s.normalized_json,'$.service'))))>0))
 AND (?='' OR outcome=?) AND (?='' OR cdn=?) AND (?='' OR cloud=?)
 ) `
	keyword := strings.TrimSpace(q.Keyword)
	args := []any{projectID, runID, runID, runID, projectID, runID, projectID, runID, projectID, keyword, keyword, projectID, keyword, q.Outcome, q.Outcome, q.CDN, q.CDN, q.Cloud, q.Cloud}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, cte+`SELECT COUNT(*),COALESCE(SUM(outcome='responded'),0),
 COALESCE(SUM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(data,'$.name')),'') NOT IN ('',url)),0),
 COALESCE(SUM(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(data,'$.fingerprint')),'')<>''),0) FROM filtered`, args...).Scan(&out.Summary.Total, &out.Summary.Responded, &out.Summary.Titled, &out.Summary.Fingerprinted)
	if err != nil {
		return out, err
	}
	out.Total = out.Summary.Total
	pageArgs := append(append([]any{}, args...), projectID, projectID, q.Size, (q.Page-1)*q.Size)
	rows, err := tx.QueryContext(ctx, cte+`SELECT f.asset_id,f.run_id,f.observed_at,f.info_observed_at,f.data,f.enrichment_state,f.enrichment_error,f.network_data,f.provider,f.active_probe,
 COALESCE((SELECT JSON_ARRAYAGG(JSON_UNQUOTE(JSON_EXTRACT(s.normalized_json,'$.service'))) FROM discovery_observation s
 WHERE s.project_id=? AND s.run_id=f.info_run_id AND s.kind='exposure' AND s.deleted_at='1970-01-01 00:00:00'
 AND JSON_UNQUOTE(JSON_EXTRACT(s.normalized_json,'$.exposure_type'))='service'
 AND JSON_UNQUOTE(JSON_EXTRACT(s.normalized_json,'$.url'))=f.url),JSON_ARRAY()),
 COALESCE(m.owner,''),COALESCE(m.business_unit,''),COALESCE(m.status,'')
 FROM filtered f LEFT JOIN asset m ON m.id=f.asset_id AND m.project_id=?
 ORDER BY `+orderBy(q.Sort)+` LIMIT ? OFFSET ?`, pageArgs...)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var item Website
		var data, names, networkData []byte
		var owner, businessUnit, assetStatus string
		if err := rows.Scan(&item.AssetID, &item.RunID, &item.ObservedAt, &item.InfoObservedAt, &data, &item.EnrichmentState, &item.EnrichmentError, &networkData, &item.Provider, &item.ActiveProbe, &names, &owner, &businessUnit, &assetStatus); err != nil {
			rows.Close()
			return out, err
		}
		decoded, err := decodeWebsite(data, names)
		if err != nil {
			rows.Close()
			return out, err
		}
		decoded.AssetID = item.AssetID
		decoded.RunID = item.RunID
		decoded.ObservedAt = item.ObservedAt
		decoded.InfoObservedAt = item.InfoObservedAt
		decoded.Provider = item.Provider
		decoded.ActiveProbe = item.ActiveProbe
		decoded.Owner = owner
		decoded.BusinessUnit = businessUnit
		decoded.AssetStatus = assetStatus
		decoded.applyEnrichment(item.EnrichmentState, item.EnrichmentError, networkData)
		out.Items = append(out.Items, decoded)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// orderBy returns a fixed ORDER BY clause; q.Sort is validated before use and
// never interpolated. The trailing url/id keys keep pagination stable when many
// sites share one observation time.
func orderBy(sort string) string {
	const stable = "f.observed_at DESC,f.url,f.id DESC,f.asset_id DESC"
	if sort == SortRecent {
		return stable
	}
	// A title outranks a bare response: a crawled title with no status code is
	// still a site someone can recognise, while an untitled 200 is not.
	const titled = "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(f.data,'$.name')),'') NOT IN ('',f.url)"
	return `CASE
 WHEN ` + titled + ` AND JSON_UNQUOTE(JSON_EXTRACT(f.data,'$.value')) REGEXP '^[45][0-9][0-9]$' THEN 1
 WHEN ` + titled + ` THEN 0
 WHEN f.outcome='responded' THEN 2
 ELSE 3 END,` + stable
}
