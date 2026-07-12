package baiyan

import "testing"

func TestGenerateAlterxCandidates(t *testing.T) {
	cands, wordCount := generateAlterxCandidates("x.com", []string{"dev-api.x.com", "prod-web.x.com"})
	if wordCount != 4 {
		t.Fatalf("词表 size = %d, want 4", wordCount)
	}
	set := make(map[string]bool)
	for _, c := range cands {
		set[c] = true
	}
	if !set["prod-api.x.com"] {
		t.Errorf("缺交叉 prod-api.x.com")
	}
	if !set["dev-web.x.com"] {
		t.Errorf("缺交叉 dev-web.x.com")
	}
	if set["dev-api.x.com"] {
		t.Errorf("已知 dev-api.x.com 未排除")
	}
	if set["prod-web.x.com"] {
		t.Errorf("已知 prod-web.x.com 未排除")
	}
	if !set["dev.x.com"] {
		t.Errorf("缺单 token dev.x.com")
	}
}

func TestGenerateAlterxCandidatesSmallCorpus(t *testing.T) {
	cands, _ := generateAlterxCandidates("x.com", []string{"a.x.com"})
	if cands != nil {
		t.Errorf("词表<2 应返回 nil, got %v", cands)
	}
	// 用户例子:a.b.com 单子域,零可拆 token → nil
	cands, _ = generateAlterxCandidates("a.b.com", []string{"a.b.com"})
	if cands != nil {
		t.Errorf("零 token 应返回 nil, got %v", cands)
	}
}
