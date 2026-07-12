package baiyan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 风鸟(riskbird.com)只用于提供"公司层级关系"(对外投资 companyInvest)，
// 供 -c --deep 子公司扩张使用。各公司的 ICP 备案统一由 ICP_Query 查询，不走风鸟 propertyIcp。

const (
	rbSearchURL = "https://www.riskbird.com/riskbird-api/newSearch"
	rbEntURL    = "https://www.riskbird.com/api/ent/query"
	rbListURL   = "https://www.riskbird.com/riskbird-api/companyInfo/list"
)

// parseRatio 把风鸟的 funderRatio("100%"/"60.5%")解析成数值。
func parseRatio(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%")), 64)
	return f
}

// rbSearchEntid 按公司名搜索，返回首个匹配的 entid。
func (a *App) rbSearchEntid(ctx context.Context, name string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"searchKey": name, "pageNo": "1", "range": "10",
		"referer": "search", "queryType": "1",
		"selectConditionData": `{"status":"","sort_field":""}`,
	})
	data, err := a.rbRequest(ctx, http.MethodPost, rbSearchURL, string(body))
	if err != nil {
		return "", err
	}
	var resp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			List []struct {
				Entid   string `json:"entid"`
				EntName string `json:"entName"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("解析失败: %w", err)
	}
	if resp.Code != 20000 || len(resp.Data.List) == 0 {
		return "", fmt.Errorf("风鸟未找到该公司(code=%d %s)", resp.Code, resp.Msg)
	}
	return resp.Data.List[0].Entid, nil
}

// rbOrderNo 用 entid 换取真正用于 companyInfo/list 的 orderNo。
func (a *App) rbOrderNo(ctx context.Context, entid string) (string, error) {
	data, err := a.rbRequest(ctx, http.MethodGet, rbEntURL+"?entId="+entid, "")
	if err != nil {
		return "", err
	}
	var resp struct {
		OrderNo string `json:"orderNo"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("解析失败: %w", err)
	}
	if resp.OrderNo == "" {
		return "", errors.New("未取到 orderNo")
	}
	return resp.OrderNo, nil
}

// rbListAll 翻页拉取某个 extractType 的全部记录(最多 10 页兜底)。
func (a *App) rbListAll(ctx context.Context, orderNo, extractType string) ([]map[string]any, error) {
	var all []map[string]any
	for page := 1; page <= 10; page++ {
		items, total, err := a.rbList(ctx, orderNo, extractType, page)
		if err != nil {
			return all, err
		}
		all = append(all, items...)
		if len(items) == 0 || len(all) >= total || page >= 10 {
			break
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return all, ctx.Err()
		}
	}
	return all, nil
}

// rbList 单页查询 companyInfo/list。
func (a *App) rbList(ctx context.Context, orderNo, extractType string, page int) ([]map[string]any, int, error) {
	body, _ := json.Marshal(map[string]string{
		"filterCnd": "1", "page": strconv.Itoa(page), "size": "100",
		"orderNo": orderNo, "extractType": extractType, "sortField": "",
	})
	data, err := a.rbRequest(ctx, http.MethodPost, rbListURL, string(body))
	if err != nil {
		return nil, 0, err
	}
	var resp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			TotalCount int              `json:"totalCount"`
			ApiData    []map[string]any `json:"apiData"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, 0, fmt.Errorf("解析失败: %w", err)
	}
	if resp.Code != 20000 {
		return nil, 0, fmt.Errorf("风鸟 code=%d msg=%s", resp.Code, resp.Msg)
	}
	return resp.Data.ApiData, resp.Data.TotalCount, nil
}

// rbRequest 统一带风鸟 Cookie + 必需头的请求。
func (a *App) rbRequest(ctx context.Context, method, url, body string) ([]byte, error) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, url, r)
	if err != nil {
		return nil, err
	}
	h := req.Header
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36")
	h.Set("Accept", "text/html,application/json,application/xhtml+xml, image/jxr, */*")
	h.Set("App-Device", "WEB")
	h.Set("Content-Type", "application/json")
	h.Set("Cookie", a.spaceConfig.RiskbirdCookie)
	h.Set("Origin", "https://www.riskbird.com")
	h.Set("Referer", "https://www.riskbird.com/ent/")
	if !strings.Contains(url, "newSearch") {
		h.Set("Xs-Content-Type", "application/json")
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
