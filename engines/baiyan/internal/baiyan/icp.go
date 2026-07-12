package baiyan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// runICP executes standalone ICP-filing query mode (-icp).
// The -icp value is either a literal 备案号 or a path to a file holding one per line.
// Each 备案号 is queried against FOFA / Quake / Hunter; any single engine failure
// (down, no quota, missing key) is logged and skipped. Results are merged into
// deduped registrable domains and written to beian<timestamp>.txt.
func (a *App) runICP(ctx context.Context) error {
	targets, err := a.loadICPTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("icp 输入为空")
	}
	a.progress.Log("[ICP] 备案查询模式，待查备案号 %d 个（三引擎各自容错，失败跳过；优先域名，该备案号无域名才回退 IP）", len(targets))

	result := NewOrderedSet()
	for i, beian := range targets {
		beian = strings.TrimSpace(beian)
		if beian == "" {
			continue
		}
		a.progress.Log("[ICP] %d/%d 查询 %s", i+1, len(targets), beian)

		// 按备案号分桶：domains 优先；仅当该备案号一个域名都没有时才保留 ips
		domains := NewOrderedSet()
		ips := NewOrderedSet()

		if err := a.fofaQueryICP(ctx, beian, domains, ips); err != nil {
			a.progress.Log("[WARN] [ICP] FOFA 查询 %s 失败，跳过: %v", beian, err)
		}
		if err := a.quakeQueryICP(ctx, beian, domains, ips); err != nil {
			a.progress.Log("[WARN] [ICP] Quake 查询 %s 失败，跳过: %v", beian, err)
		}
		if err := a.hunterQueryICP(ctx, beian, domains, ips); err != nil {
			a.progress.Log("[WARN] [ICP] Hunter 查询 %s 失败，跳过: %v", beian, err)
		}

		if domains.Len() > 0 {
			result.AddMany(domains.Items())
		} else {
			result.AddMany(ips.Items())
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	outPath := filepath.Join(a.rootDir, fmt.Sprintf("beian%s.txt", time.Now().Format("20060102_150405")))
	if err := writeLines(outPath, result.Items()); err != nil {
		return fmt.Errorf("写入备案结果失败: %w", err)
	}
	a.progress.Log("[ICP] 完成，结果 %d 条，结果文件: %s", result.Len(), outPath)
	return nil
}

// loadICPTargets resolves the -icp value via the shared resolveInputValue helper
// (existing file → read lines; otherwise single literal 备案号).
func (a *App) loadICPTargets() ([]string, error) {
	return resolveInputValue(a.opts.ICP)
}

// looksLikeDomain reports whether s is a plausible domain: it must contain a dot
// and its TLD must contain at least one letter. This rejects empty strings, bare
// IPs, and numeric fragments like "47.122" that leak in from IP-only assets.
func looksLikeDomain(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if !strings.Contains(s, ".") {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, r := range parts[len(parts)-1] {
		if r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

// addHostTarget normalizes a raw host/ip value and routes it into domains or ips:
// a bare IP → ips (port stripped); otherwise the registrable domain → domains.
// Garbage is dropped.
func addHostTarget(domains, ips *OrderedSet, raw string) {
	h := cleanHost(raw)
	if h == "" {
		return
	}
	if net.ParseIP(h) != nil {
		ips.Add(h)
		return
	}
	if d := extractMainDomain(h); looksLikeDomain(d) {
		domains.Add(d)
	}
}

// fofaQueryICP queries FOFA with icp="<备案号>" and appends domains/IPs.
// fofaSearch row[0] is the host field, which holds either a domain or an ip:port.
func (a *App) fofaQueryICP(ctx context.Context, beian string, domains, ips *OrderedSet) error {
	rows, err := a.fofaSearch(ctx, fmt.Sprintf(`icp="%s"`, beian))
	if err != nil {
		return err
	}
	for _, row := range rows {
		if len(row) > 0 {
			addHostTarget(domains, ips, row[0])
		}
	}
	return nil
}

// quakeQueryICP queries Quake with icp:"<备案号>" and appends domains/IPs.
func (a *App) quakeQueryICP(ctx context.Context, beian string, domains, ips *OrderedSet) error {
	rows, err := a.quakeSearch(ctx, fmt.Sprintf(`icp:"%s"`, beian))
	if err != nil {
		return err
	}
	for _, row := range rows {
		if v, ok := row["domain"].(string); ok {
			addHostTarget(domains, ips, v)
		}
		if v, ok := row["ip"].(string); ok {
			addHostTarget(domains, ips, v)
		}
	}
	return nil
}

// hunterQueryICP queries Hunter with icp.number="<备案号>" and appends domains/IPs.
// Dedicated (not reusing hunterSearch) because hunterSearch hardcodes domain.suffix=
// and applies a raw-body regex fallback that would pollute ICP results.
func (a *App) hunterQueryICP(ctx context.Context, beian string, domains, ips *OrderedSet) error {
	if a.spaceConfig.HunterKey == "" {
		return errors.New("Hunter 配置缺失")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`icp.number="%s"`, beian)))

	page := 1
	pageSize := 100
	limit := a.spaceConfig.HunterNum
	if limit <= 0 {
		limit = 1000
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		endpoint := fmt.Sprintf(
			"https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d&is_web=1",
			url.QueryEscape(a.spaceConfig.HunterKey),
			url.QueryEscape(encoded),
			page,
			pageSize,
		)

		reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("User-Agent", "Baiyan-Go/1.0")

		resp, err := a.httpClient.Do(req)
		if err != nil {
			cancel()
			return err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		if err != nil {
			return err
		}
		if resp.StatusCode >= 400 {
			return fmt.Errorf("Hunter HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var hunterResp struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Total int `json:"total"`
				Arr   []struct {
					Domain string `json:"domain"`
					IP     string `json:"ip"`
				} `json:"arr"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &hunterResp); err != nil {
			return fmt.Errorf("解析 Hunter 响应失败: %w", err)
		}
		if hunterResp.Code != 200 {
			msg := hunterResp.Message
			if msg == "" {
				msg = "Hunter 查询失败"
			}
			return errors.New(msg)
		}

		for _, item := range hunterResp.Data.Arr {
			addHostTarget(domains, ips, item.Domain)
			addHostTarget(domains, ips, item.IP)
		}

		total := hunterResp.Data.Total
		if page*pageSize >= total || len(hunterResp.Data.Arr) == 0 || page*pageSize >= limit {
			break
		}
		page++
		time.Sleep(1 * time.Second)
	}
	return nil
}
