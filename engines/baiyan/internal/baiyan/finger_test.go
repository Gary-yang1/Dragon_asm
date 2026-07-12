package baiyan

import "testing"

func TestParseObserverWardRecords(t *testing.T) {
	lines := []string{
		`[ http://oa.600576.com:9081 | ["apache-shiro"] | 2467 | 200 | 运维平台 ]`,
		`[ http://60.190.175.98:6012 | ["colorfulcube-traffic-management"] | 10392 | 200 |`,
		`瑞云ddi平台`,
		`]`,
	}

	records := parseObserverWardRecords(lines)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	first := records[0]
	if first.URL != "http://oa.600576.com:9081" {
		t.Fatalf("unexpected url: %q", first.URL)
	}
	if first.Name != "apache-shiro" {
		t.Fatalf("unexpected name: %q", first.Name)
	}
	if first.Length != "2467" || first.StatusCode != "200" {
		t.Fatalf("unexpected basic fields: %#v", first)
	}
	if first.Title != "运维平台" {
		t.Fatalf("unexpected title: %q", first.Title)
	}

	second := records[1]
	if second.Title != "瑞云ddi平台" {
		t.Fatalf("unexpected multiline title: %q", second.Title)
	}
}
