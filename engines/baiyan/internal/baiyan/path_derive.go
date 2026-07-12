package baiyan

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// singleLabelTLDs 单段顶级域名/公共后缀,用于主机名 label 过滤。
// 多段后缀(com.cn/gov.cn/edu.cn/co.uk 等)复用 oneforall_go.go 的 multiPartSuffixes。
var singleLabelTLDs = map[string]bool{
	// 通用顶级域
	"com": true, "net": true, "org": true, "edu": true, "gov": true, "mil": true, "int": true,
	"info": true, "biz": true, "name": true, "pro": true, "xyz": true, "top": true, "club": true,
	"online": true, "site": true, "store": true, "tech": true, "app": true, "dev": true,
	"ai": true, "io": true, "co": true, "me": true, "cc": true, "tv": true, "wiki": true,
	"live": true, "world": true, "vip": true, "link": true, "zone": true, "host": true,
	// 国家代码
	"cn": true, "jp": true, "kr": true, "uk": true, "us": true, "de": true, "fr": true,
	"ru": true, "au": true, "ca": true, "br": true, "in": true, "tw": true, "hk": true,
	"sg": true, "it": true, "es": true, "nl": true, "se": true, "no": true, "fi": true,
	"ch": true, "at": true, "be": true, "dk": true, "pl": true, "tr": true, "gr": true,
	"pt": true, "ie": true, "mx": true, "ar": true, "za": true, "th": true, "id": true,
	"vn": true, "my": true, "ph": true, "nz": true,
}

// deriveHostPaths 拆 host label(先按点,再按横线),剥离 TLD/公共后缀,返回 /token 路径候选。
// 例:a.b.com → [/a /b];c-d.com → [/c-d /c /d];a.b.com.cn → [/a /b]。
// 纯函数,便于单测。
func deriveHostPaths(host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.Trim(host, ".")
	if host == "" {
		return nil
	}
	if net.ParseIP(host) != nil { // IP 无 label,跳过
		return nil
	}

	labels := strings.Split(host, ".")
	// 循环剥离 TLD(单段)与公共后缀(双段),应对 a.b.com.cn 这种多段尾
	for {
		n := len(labels)
		if n == 0 {
			break
		}
		if n >= 2 && multiPartSuffixes[labels[n-2]+"."+labels[n-1]] {
			labels = labels[:n-2]
			continue
		}
		if singleLabelTLDs[labels[n-1]] {
			labels = labels[:n-1]
			continue
		}
		break
	}
	if len(labels) == 0 {
		return nil
	}

	set := NewOrderedSet()
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		set.Add("/" + label) // 原段
		for _, sub := range strings.Split(label, "-") { // 横线拆子 token
			sub = strings.TrimSpace(sub)
			if sub != "" {
				set.Add("/" + sub)
			}
		}
	}
	return set.Items()
}

// probeDerivedPaths 对存活 URL 列表跑主机名派生路径探测。
// 同 host 只派生一次;IP host 跳过;命中(非 WAF/空壳/假200)返回新 URL。
// 仅探一层,命中产生的新 URL 不再递归派生。
func (a *App) probeDerivedPaths(ctx context.Context, urls []string) []string {
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: a.httpClient.Transport,
	}

	var jobs []string
	seenHost := NewOrderedSet()
	for _, raw := range urls {
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := parsed.Hostname()
		if host == "" || net.ParseIP(host) != nil {
			continue
		}
		if !seenHost.Add(host) { // 同 host 去重
			continue
		}
		scheme := parsed.Scheme
		if scheme == "" {
			scheme = "https"
		}
		for _, p := range deriveHostPaths(host) {
			jobs = append(jobs, scheme+"://"+host+p)
		}
	}
	if len(jobs) == 0 {
		return nil
	}

	results := NewOrderedSet()
	var mu sync.Mutex
	sem := make(chan struct{}, a.opts.Threads)
	var wg sync.WaitGroup

	for _, target := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			u := probeSingleHTTP(ctx, client, t)
			if u != "" {
				mu.Lock()
				results.Add(u)
				mu.Unlock()
			}
		}(target)
	}
	wg.Wait()
	return results.Items()
}
