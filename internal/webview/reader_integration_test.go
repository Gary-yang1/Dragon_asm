package webview

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/go-sql-driver/mysql"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWebsiteSnapshotsMySQL(t *testing.T) {
	dsn := os.Getenv("ASM_WEBVIEW_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated database not configured")
	}
	cfg, e := mysql.ParseDSN(dsn)
	if e != nil || !strings.HasPrefix(cfg.DBName, "asm_webview_test_") {
		t.Fatal("dedicated database required")
	}
	db, e := sql.Open("mysql", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	for _, ddl := range []string{`CREATE TABLE asset(id BIGINT PRIMARY KEY,project_id BIGINT,asset_key VARCHAR(512),asset_type VARCHAR(32),value VARCHAR(1024),owner VARCHAR(64) NOT NULL DEFAULT '',business_unit VARCHAR(128) NOT NULL DEFAULT '',status VARCHAR(16) NOT NULL DEFAULT 'active',last_seen DATETIME,deleted_at DATETIME DEFAULT '1970-01-01 00:00:00')`, `CREATE TABLE discovery_observation(id BIGINT PRIMARY KEY,project_id BIGINT,run_id BIGINT,kind VARCHAR(32),provider VARCHAR(64) NOT NULL DEFAULT 'active_api',active_probe BOOLEAN NOT NULL DEFAULT TRUE,observed_at DATETIME,normalized_json JSON,deleted_at DATETIME DEFAULT '1970-01-01 00:00:00')`, `CREATE TABLE web_network_enrichment(observation_id BIGINT PRIMARY KEY,project_id BIGINT,run_id BIGINT,state VARCHAR(32),result_json JSON,error_summary VARCHAR(512),source_hash CHAR(64) NOT NULL)`} {
		if _, e = db.Exec(ddl); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC()
	_, e = db.Exec(`INSERT INTO asset(id,project_id,asset_key,asset_type,value,last_seen) VALUES (1,1,'web:http://example.test','web','http://example.test',?),(2,1,'web:http://manual.test','web','http://manual.test',?)`, now, now)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range []struct {
		id, pid, run int
		name, code   string
		at           time.Time
	}{{1, 1, 1, "Original title", "200", now.Add(-time.Hour)}, {2, 1, 2, "http://example.test", "unknown", now}, {3, 2, 1, "Foreign title", "200", now.Add(time.Hour)}} {
		data, _ := json.Marshal(map[string]any{"url": "http://example.test", "name": r.name, "value": r.code, "exposure_type": "web", "parent": map[string]string{"natural_key": "web:http://example.test"}, "fingerprint": "nginx"})
		if _, e = db.Exec(`INSERT INTO discovery_observation(id,project_id,run_id,kind,observed_at,normalized_json) VALUES (?,?,?,'exposure',?,?)`, r.id, r.pid, r.run, r.at, string(data)); e != nil {
			t.Fatal(e)
		}
	}
	q := Query{Page: 1, Size: 20}
	ctx := context.Background()
	p, e := List(ctx, db, 1, 1, q)
	if e != nil || p.Total != 1 || p.Items[0].Title != "Original title" {
		t.Fatalf("historical snapshot: %+v %v", p, e)
	}
	p, e = List(ctx, db, 1, 2, q)
	if e != nil || p.Items[0].Title != "" || p.Items[0].Outcome != "unknown" {
		t.Fatalf("failed snapshot rewritten: %+v %v", p, e)
	}
	p, e = List(ctx, db, 1, 0, Query{Page: 1, Size: 20, Keyword: "Original title"})
	if e != nil || p.Total != 1 || p.Items[0].Outcome != "unknown" || p.Items[0].InfoObservedAt == nil {
		t.Fatalf("last successful info lost: %+v %v", p, e)
	}
	p, e = List(ctx, db, 1, 0, q)
	if e != nil || p.Total != 2 {
		t.Fatalf("manual asset omitted: %+v %v", p, e)
	}
	p, e = List(ctx, db, 1, 0, Query{Page: 1, Size: 20, Keyword: "Foreign"})
	if e != nil || p.Total != 0 {
		t.Fatal("cross-project data leak", e)
	}
	network := `{"status":"partial","resolved_ips":["192.0.2.18"],"cname_chain":["edge.cloudfront.net"],"cdn":{"status":"identified","provider":"CloudFront"},"cloud":{"status":"identified","provider":"AWS"},"observed_at":"2026-09-16T01:05:00Z"}`
	if _, e = db.Exec(`INSERT INTO web_network_enrichment (observation_id,project_id,run_id,state,result_json,error_summary,source_hash)
 SELECT id,project_id,run_id,IF(id=1,'complete','pending'),IF(id=1,CAST(? AS JSON),NULL),IF(id=1,'','Temporary lookup failure'),SHA2(CAST(normalized_json AS CHAR),256)
 FROM discovery_observation WHERE id IN (1,2)`, network); e != nil {
		t.Fatal(e)
	}
	p, e = List(ctx, db, 1, 1, Query{Page: 1, Size: 20, CDN: "identified", Cloud: "identified", Keyword: "192.0.2.18"})
	if e != nil || p.Total != 1 || p.Items[0].NetworkSource != "baiyan" || p.Items[0].Outcome != "responded" || p.Items[0].Title != "Original title" || p.Items[0].ConnectedIP != "" {
		t.Fatalf("network search or history enrichment failed: %+v %v", p, e)
	}
	for _, keyword := range []string{"CloudFront", "AWS", "edge.cloudfront.net"} {
		p, e = List(ctx, db, 1, 1, Query{Page: 1, Size: 20, Keyword: keyword})
		if e != nil || p.Total != 1 {
			t.Fatalf("network search %s failed: %+v %v", keyword, p, e)
		}
	}
	p, e = List(ctx, db, 1, 2, q)
	if e != nil || p.Items[0].EnrichmentState != "pending" || p.Items[0].NetworkSource != "" || len(p.Items[0].ResolvedIPs) != 0 {
		t.Fatalf("old run network data leaked into new run: %+v %v", p, e)
	}
	p, e = List(ctx, db, 1, 0, Query{Page: 1, Size: 20, CDN: "identified"})
	if e != nil || p.Total != 0 {
		t.Fatalf("latest view borrowed unrelated network snapshot: %+v %v", p, e)
	}
	if _, e = db.Exec(`UPDATE web_network_enrichment SET project_id=2,state='complete',result_json=? WHERE observation_id=2`, network); e != nil {
		t.Fatal(e)
	}
	p, e = List(ctx, db, 1, 2, q)
	if e != nil || p.Items[0].EnrichmentState != "not_started" || p.Items[0].NetworkSource != "" {
		t.Fatalf("foreign enrichment accepted: %+v %v", p, e)
	}
	if _, e = db.Exec(`UPDATE discovery_observation SET normalized_json=JSON_SET(normalized_json,'$.name','Updated source title') WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	p, e = List(ctx, db, 1, 1, q)
	if e != nil || p.Total != 1 || p.Items[0].Title != "Updated source title" || p.Items[0].EnrichmentState != "failed" || p.Items[0].EnrichmentError == "" || p.Items[0].NetworkSource != "" || len(p.Items[0].ResolvedIPs) != 0 || p.Items[0].CDN.Status != "unknown" {
		t.Fatalf("changed source reused stale network evidence: %+v %v", p, e)
	}
	p, e = List(ctx, db, 1, 1, Query{Page: 1, Size: 20, Keyword: "192.0.2.18"})
	if e != nil || p.Total != 0 {
		t.Fatalf("stale network evidence remained searchable: %+v %v", p, e)
	}
	if _, e = db.Exec(`UPDATE web_network_enrichment SET project_id=1 WHERE observation_id=2`); e != nil {
		t.Fatal(e)
	}
	p, e = List(ctx, db, 1, 0, Query{Page: 1, Size: 20, Keyword: "Updated source title"})
	if e != nil || p.Total != 1 || p.Items[0].EnrichmentState != "complete" || p.Items[0].NetworkSource != "baiyan" || p.Items[0].InfoObservedAt == nil {
		t.Fatalf("title fallback changed original network correlation: %+v %v", p, e)
	}

	// One run where every site shares a timestamp, as a real batch does.
	batch := now.Add(-2 * time.Hour)
	sites := []struct {
		id         int
		url, title string
		code       string
	}{
		{31, "http://a.test", "", "unknown"},          // no status reported
		{32, "http://b.test", "Real page", "200"},     // titled response
		{33, "http://c.test", "Access Denied", "403"}, // titled error page
		{34, "http://d.test", "http://d.test", "200"}, // response without a title
		{35, "http://e.test", "Another page", "200"},  // titled response
	}
	for _, site := range sites {
		if _, e = db.Exec(`INSERT INTO asset(id,project_id,asset_key,asset_type,value,last_seen) VALUES (?,3,?,'web',?,?)`, site.id, "web:"+site.url, site.url, batch); e != nil {
			t.Fatal(e)
		}
		data, _ := json.Marshal(map[string]any{"url": site.url, "name": site.title, "value": site.code, "exposure_type": "web", "parent": map[string]string{"natural_key": "web:" + site.url}})
		if _, e = db.Exec(`INSERT INTO discovery_observation(id,project_id,run_id,kind,observed_at,normalized_json) VALUES (?,3,9,'exposure',?,?)`, site.id, batch, string(data)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = db.Exec(`UPDATE asset SET owner='alice',business_unit='retail',status='ignored' WHERE id=32`); e != nil {
		t.Fatal(e)
	}
	urls := func(page Page) []string {
		out := make([]string, 0, len(page.Items))
		for _, item := range page.Items {
			out = append(out, item.URL)
		}
		return out
	}
	for _, runID := range []uint64{0, 9} {
		p, e = List(ctx, db, 3, runID, q)
		if want := []string{"http://b.test", "http://e.test", "http://c.test", "http://d.test", "http://a.test"}; e != nil || strings.Join(urls(p), " ") != strings.Join(want, " ") {
			t.Fatalf("run %d value order = %v, want %v (%v)", runID, urls(p), want, e)
		}
		if p.Items[0].Owner != "alice" || p.Items[0].BusinessUnit != "retail" || p.Items[0].AssetStatus != "ignored" || p.Items[1].Owner != "" || p.Items[1].AssetStatus != "active" {
			t.Fatalf("run %d asset management fields: %+v", runID, p.Items[:2])
		}
	}
	p, e = List(ctx, db, 3, 9, Query{Page: 1, Size: 20, Sort: SortRecent})
	if want := []string{"http://a.test", "http://b.test", "http://c.test", "http://d.test", "http://e.test"}; e != nil || strings.Join(urls(p), " ") != strings.Join(want, " ") {
		t.Fatalf("recent order = %v, want %v (%v)", urls(p), want, e)
	}
	p, e = List(ctx, db, 3, 9, Query{Page: 2, Size: 2})
	if want := []string{"http://c.test", "http://d.test"}; e != nil || strings.Join(urls(p), " ") != strings.Join(want, " ") || p.Total != 5 {
		t.Fatalf("second page = %v, want %v (%v)", urls(p), want, e)
	}
	if _, e = List(ctx, db, 3, 9, Query{Page: 1, Size: 20, Sort: "title; DROP TABLE asset"}); e != ErrQuery {
		t.Fatalf("unknown sort accepted: %v", e)
	}

	// Search-engine crawls (passive, no status code) next to live probes.
	probed := now.Add(-3 * time.Hour)
	observations := []struct {
		id          int
		url, title  string
		code        string
		provider    string
		activeProbe bool
		at          time.Time
	}{
		{41, "http://x1.test:80", "Live title", "200", "active_api", true, probed},
		{42, "http://x1.test:80", "Crawled title", "unknown", "fofa", false, probed.Add(time.Hour)},
		{43, "http://x2.test:80", "Crawled only", "unknown", "fofa", false, probed.Add(time.Hour)},
		{44, "http://x3.test:80", "", "200", "active_api", true, probed},
		{45, "http://x4.test:80", "", "unknown", "active_api", true, probed},
		{46, "http://x4.test:80", "Borrowed", "unknown", "fofa", false, probed.Add(-time.Hour)},
	}
	for i, url := range []string{"http://x1.test:80", "http://x2.test:80", "http://x3.test:80", "http://x4.test:80"} {
		if _, e = db.Exec(`INSERT INTO asset(id,project_id,asset_key,asset_type,value,last_seen) VALUES (?,4,?,'web',?,?)`, 51+i, "web:"+url, url, probed); e != nil {
			t.Fatal(e)
		}
	}
	for _, o := range observations {
		data, _ := json.Marshal(map[string]any{"url": o.url, "name": o.title, "value": o.code, "exposure_type": "web", "parent": map[string]string{"natural_key": "web:" + o.url}})
		if _, e = db.Exec(`INSERT INTO discovery_observation(id,project_id,run_id,kind,provider,active_probe,observed_at,normalized_json) VALUES (?,4,?,'exposure',?,?,?,?)`, o.id, o.id, o.provider, o.activeProbe, o.at, string(data)); e != nil {
			t.Fatal(e)
		}
	}
	p, e = List(ctx, db, 4, 0, q)
	if want := []string{"http://x2.test:80", "http://x1.test:80", "http://x4.test:80", "http://x3.test:80"}; e != nil || strings.Join(urls(p), " ") != strings.Join(want, " ") {
		t.Fatalf("crawl-aware order = %v, want %v (%v)", urls(p), want, e)
	}
	byURL := map[string]Website{}
	for _, item := range p.Items {
		byURL[item.URL] = item
	}
	if x1 := byURL["http://x1.test:80"]; x1.Title != "Live title" || x1.StatusCode != 200 || x1.Provider != "active_api" || !x1.ActiveProbe {
		t.Fatalf("newer crawl replaced the live probe: %+v", x1)
	}
	if x2 := byURL["http://x2.test:80"]; x2.Title != "Crawled only" || x2.Provider != "fofa" || x2.ActiveProbe || x2.Outcome != "unknown" || x2.InfoObservedAt != nil {
		t.Fatalf("crawl-only site: %+v", x2)
	}
	if x4 := byURL["http://x4.test:80"]; x4.Title != "Borrowed" || !x4.ActiveProbe || x4.InfoObservedAt == nil {
		t.Fatalf("crawled title not lent to an untitled probe: %+v", x4)
	}
}
