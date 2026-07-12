package baiyan

import (
	"context"
	"strconv"
	"strings"
	"sync"
)

// alterxMaxCandidates 限制单目标派生候选总数,防止词表交叉爆炸拖垮 DNS。
const alterxMaxCandidates = 5000

// alterxDerive 从存活子域拆 token 建词表,交叉重组派生新子域,DNS 验证存活。
// 纯学习目标自身命名规律(alterx 式),与固定词缀的 collectAltdnsSubdomains 不同。
// 语料过少(词表 < 2)直接返回 nil。
func (a *App) alterxDerive(ctx context.Context, domain string, knownSubs []string) []string {
	candidates, wordCount := generateAlterxCandidates(domain, knownSubs)
	if len(candidates) == 0 {
		return nil
	}
	if wordCount > 0 {
		a.progress.Log("[ALTERX] %s 词表 %d 个 token,派生候选 %d 个", domain, wordCount, len(candidates))
	}
	if len(candidates) > alterxMaxCandidates {
		a.progress.Log("[ALTERX] %s 候选达上限 %d,已截断", domain, alterxMaxCandidates)
		candidates = candidates[:alterxMaxCandidates]
	}

	result := NewOrderedSet()
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)

	for _, cand := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			ips, err := a.resolveIPv4s(ctx, host)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				result.Add(host)
				mu.Unlock()
			}
		}(cand)
	}
	wg.Wait()

	return filterSubdomainsForDomain(domain, result.Items())
}

// generateAlterxCandidates 是 alterxDerive 的纯函数核心,便于单测。
// 返回候选子域(完整,含 domain 后缀)与词表大小。
func generateAlterxCandidates(domain string, knownSubs []string) ([]string, int) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	known := NewOrderedSet()
	words := NewOrderedSet()

	for _, s := range knownSubs {
		s = strings.ToLower(strings.TrimSpace(s))
		known.Add(s)
		if s != domain && !strings.HasSuffix(s, "."+domain) {
			continue
		}
		prefix := strings.TrimSuffix(s, "."+domain)
		prefix = strings.Trim(prefix, ".")
		if prefix == "" {
			continue
		}
		for _, tok := range strings.FieldsFunc(prefix, func(r rune) bool { return r == '.' || r == '-' }) {
			tok = strings.TrimSpace(tok)
			if len(tok) < 2 {
				continue
			}
			if _, err := strconv.Atoi(tok); err == nil { // 跳纯数字
				continue
			}
			words.Add(tok)
		}
	}

	if words.Len() < 2 {
		return nil, words.Len()
	}
	wordList := words.Items()

	candidates := NewOrderedSet()
	addCand := func(prefix string) {
		if candidates.Len() >= alterxMaxCandidates {
			return
		}
		host := prefix + "." + domain
		if known.Contains(host) {
			return
		}
		candidates.Add(host)
	}

	// 单 token + 数字扩展
	for _, w := range wordList {
		addCand(w)
		for n := 1; n <= 3; n++ {
			addCand(w + strconv.Itoa(n))
		}
	}
	// 双 token 交叉(横线连接 + 直连)
	for _, w1 := range wordList {
		for _, w2 := range wordList {
			if w1 == w2 {
				continue
			}
			addCand(w1 + "-" + w2)
			addCand(w1 + w2)
		}
	}

	return candidates.Items(), words.Len()
}
