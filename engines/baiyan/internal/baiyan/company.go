package baiyan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	// Go 1.19 的 math/rand 默认 seed=1，手动播种让翻页延时每次运行都不同
	rand.Seed(time.Now().UnixNano())
}

// resolveInputValue 把一个入参解析为目标列表：已存在文件 → 按行读(去重)；否则当单个字面量。
// -c (公司名) 与 -icp (备案号) 共用这套判定。
func resolveInputValue(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("输入为空")
	}
	if info, err := os.Stat(value); err == nil && !info.IsDir() {
		lines, err := readLines(value)
		if err != nil {
			return nil, fmt.Errorf("读取输入文件失败: %w", err)
		}
		return lines, nil
	}
	return []string{value}, nil
}

// runCompany: 公司名 → ICP_Query 备案 → beianhao.txt + domain.txt
// --deep 0=仅母公司；≥1 用风鸟拉子公司(按 --ratio 过滤)逐层扩张，每个子公司同样走 ICP_Query 查备案。
// 固定文件名，每次覆盖。任一公司失败只 log 跳过，不中断批量。
func (a *App) runCompany(ctx context.Context) error {
	if a.spaceConfig.ICPQueryURL == "" || a.spaceConfig.ICPQueryToken == "" {
		return errors.New("ICP_Query 未配置：请在 config/spaceConfig.ini 的 [icp_query] 段填 url 和 token")
	}
	targets, err := resolveInputValue(a.opts.Company)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("company 输入为空")
	}
	deep := a.opts.Deep
	if deep < 0 {
		deep = 0
	}
	if deep > 3 { // 母/子/孙/曾孙，封顶 3 防爆炸
		deep = 3
	}
	if deep > 0 && strings.TrimSpace(a.spaceConfig.RiskbirdCookie) == "" {
		a.progress.Log("[WARN] [COMPANY] --deep≥1 需要风鸟 cookie(config [riskbird])，本次仅查母公司")
		deep = 0
	}
	a.progress.Log("[COMPANY] 公司名查询模式，待查 %d 个，深度=%d，投资占比≥%d%%", len(targets), deep, a.opts.Ratio)

	beianSet := NewOrderedSet() // 主备案号 mainLicence 去重
	hostSet := NewOrderedSet()  // 域名 + 规范化 IP
	visited := map[string]bool{}

	for i, company := range targets {
		company = strings.TrimSpace(company)
		if company == "" {
			continue
		}
		a.progress.Log("[COMPANY] %d/%d 查询 %s", i+1, len(targets), company)
		a.collectCompany(ctx, company, "", deep, visited, beianSet, hostSet)

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// 顶层公司间随机延时，降低工信部限流概率（最后一家不等）
		if i < len(targets)-1 {
			gap := time.Duration(5+rand.Intn(4)) * time.Second // 5-8s
			select {
			case <-time.After(gap):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	beianPath := filepath.Join(a.rootDir, "beianhao.txt")
	domainPath := filepath.Join(a.rootDir, "domain.txt")
	if err := writeLines(beianPath, beianSet.Items()); err != nil {
		return fmt.Errorf("写入 beianhao.txt 失败: %w", err)
	}
	if err := writeLines(domainPath, hostSet.Items()); err != nil {
		return fmt.Errorf("写入 domain.txt 失败: %w", err)
	}
	a.progress.Log("[COMPANY] 完成：主备案号 %d 个 → beianhao.txt，域名/IP %d 个 → domain.txt", beianSet.Len(), hostSet.Len())
	return nil
}

// collectCompany 收集一家公司的 ICP 备案(ICP_Query)，并按深度用风鸟递归其达标子公司。
// entid 为空(顶层公司)且需要扩张时，按公司名经风鸟搜索获取。visited 按公司名去环。
func (a *App) collectCompany(ctx context.Context, name, entid string, deep int, visited map[string]bool, beianSet, hostSet *OrderedSet) {
	if visited[name] {
		return
	}
	visited[name] = true

	// 1. 自身 ICP 备案(ICP_Query，带重试)
	records, err := a.queryCompanyICPWithRetry(ctx, name)
	if err != nil {
		a.progress.Log("[WARN] [COMPANY] %s ICP 查询失败: %v", name, err)
	} else {
		for _, rec := range records {
			if lic := strings.TrimSpace(rec.MainLicence); lic != "" {
				beianSet.Add(lic)
			}
			addCompanyHost(hostSet, rec.Domain)
		}
	}

	// 2. 风鸟子公司扩张
	if deep > 0 && strings.TrimSpace(a.spaceConfig.RiskbirdCookie) != "" {
		if entid == "" {
			if entid, err = a.rbSearchEntid(ctx, name); err != nil {
				a.progress.Log("[WARN] [COMPANY] %s 风鸟查找失败: %v", name, err)
				return
			}
		}
		orderNo, err := a.rbOrderNo(ctx, entid)
		if err != nil {
			a.progress.Log("[WARN] [COMPANY] %s 取 orderNo 失败: %v", name, err)
			return
		}
		subs, err := a.rbListAll(ctx, orderNo, "companyInvest")
		if err != nil {
			a.progress.Log("[WARN] [COMPANY] %s 子公司查询失败: %v", name, err)
			return
		}
		for _, s := range subs {
			ratio := 0.0
			if r, ok := s["funderRatio"].(string); ok {
				ratio = parseRatio(r)
			}
			if ratio < float64(a.opts.Ratio) {
				continue
			}
			sName, _ := s["entName"].(string)
			sEntid, _ := s["entid"].(string)
			if sEntid == "" {
				continue
			}
			a.progress.Log("[COMPANY]   └ %s (%.0f%%)", sName, ratio)
			select {
			case <-time.After(time.Duration(3+rand.Intn(3)) * time.Second): // 子公司间延时防 IP 封
			case <-ctx.Done():
				return
			}
			a.collectCompany(ctx, sName, sEntid, deep-1, visited, beianSet, hostSet)
		}
	}
}

// queryCompanyICPWithRetry 包一层退避重试(限流/验证码失败常为瞬时)。
func (a *App) queryCompanyICPWithRetry(ctx context.Context, company string) ([]icpRecord, error) {
	var records []icpRecord
	var err error
	const maxRetry = 2
	for attempt := 0; attempt <= maxRetry; attempt++ {
		records, err = a.queryCompanyICP(ctx, company)
		if err == nil {
			break
		}
		if attempt < maxRetry {
			backoff := time.Duration(8+rand.Intn(5)) * time.Second // 8-12s
			a.progress.Log("[COMPANY] %s 第 %d 次失败(%v)，%s 后重试", company, attempt+1, err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return records, ctx.Err()
			}
		}
	}
	return records, err
}

// icpRecord 是 ICP_Query web 查询返回的单条备案记录中我们关心的字段。
type icpRecord struct {
	MainLicence string `json:"mainLicence"`
	Domain      string `json:"domain"`
}

// queryCompanyICP 调 ICP_Query 按公司名查 web 备案，翻页汇总所有记录。
// 翻页间隔随机 8-10s，防工信部封禁。
func (a *App) queryCompanyICP(ctx context.Context, company string) ([]icpRecord, error) {
	base := strings.TrimRight(a.spaceConfig.ICPQueryURL, "/")
	const pageSize = 40
	var all []icpRecord
	page := 1

	for {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}

		target := fmt.Sprintf("%s/query/web?search=%s&pageNum=%d&pageSize=%d",
			base, url.QueryEscape(company), page, pageSize)
		body, err := a.httpGetWithToken(ctx, target)
		if err != nil {
			return all, err
		}

		var resp struct {
			Code   int    `json:"code"`
			Msg    string `json:"msg"`
			Params struct {
				HasNextPage bool        `json:"hasNextPage"`
				Pages       int         `json:"pages"`
				List        []icpRecord `json:"list"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return all, fmt.Errorf("解析 ICP_Query 响应失败: %w", err)
		}
		if resp.Code != 200 {
			return all, fmt.Errorf("ICP_Query 返回 code=%d msg=%q", resp.Code, resp.Msg)
		}

		all = append(all, resp.Params.List...)
		if !resp.Params.HasNextPage || len(resp.Params.List) == 0 || (resp.Params.Pages > 0 && page >= resp.Params.Pages) {
			break
		}
		page++

		delay := time.Duration(8+rand.Intn(3)) * time.Second // 8/9/10 秒
		a.progress.Log("[COMPANY] 翻第 %d 页，随机延时 %s 防封", page, delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return all, ctx.Err()
		}
	}
	return all, nil
}

// httpGetWithToken 带 X-Token 头 GET（ICP_Query nginx 网关要求 token）。
func (a *App) httpGetWithToken(ctx context.Context, target string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Token", a.spaceConfig.ICPQueryToken)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// addCompanyHost 规范化后加入 domain.txt：IP → 规范 IP(net.ParseIP.String)；域名 → 主域。两者都保留。
func addCompanyHost(set *OrderedSet, raw string) {
	h := cleanHost(raw)
	if h == "" {
		return
	}
	if ip := net.ParseIP(h); ip != nil {
		set.Add(ip.String()) // 规范化 IP 格式
		return
	}
	if d := extractMainDomain(h); looksLikeDomain(d) {
		set.Add(d)
	}
}
