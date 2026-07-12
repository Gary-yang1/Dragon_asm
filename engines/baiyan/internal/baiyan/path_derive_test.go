package baiyan

import (
	"reflect"
	"sort"
	"testing"
)

func sorted(s []string) []string {
	cp := append([]string(nil), s...)
	sort.Strings(cp)
	return cp
}

func TestDeriveHostPaths(t *testing.T) {
	cases := []struct {
		name string
		host string
		want []string
	}{
		{"a.b.com 过滤 com", "a.b.com", []string{"/a", "/b"}},
		{"c-d.com 横线拆+原段", "c-d.com", []string{"/c-d", "/c", "/d"}},
		{"a.b.com.cn 多段后缀", "a.b.com.cn", []string{"/a", "/b"}},
		{"b.gov.cn 剥后缀留业务段", "b.gov.cn", []string{"/b"}},
		{"纯公共后缀全剥", "gov.cn", nil},
		{"IP 跳过", "1.2.3.4", nil},
		{"空", "", nil},
	}
	for _, c := range cases {
		got := sorted(deriveHostPaths(c.host))
		want := sorted(c.want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v want %v", c.name, got, want)
		}
	}
}
