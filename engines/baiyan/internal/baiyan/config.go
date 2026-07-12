package baiyan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type SpaceConfig struct {
	FofaEmail      string
	FofaKey        string
	FofaNum        int
	QuakeToken     string
	QuakeNum       int
	HunterKey      string
	HunterNum      int
	ICPQueryURL    string
	ICPQueryToken  string
	RiskbirdCookie string
}

type SubfinderConfig struct {
	Credentials map[string][]string
}

type CredentialWarning struct {
	Source  string
	Message string
}

func loadSpaceConfig(root string) (SpaceConfig, error) {
	path := filepath.Join(root, "config", "spaceConfig.ini")
	data, err := os.ReadFile(path)
	if err != nil {
		return SpaceConfig{}, err
	}

	sections := map[string]map[string]string{}
	current := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if _, ok := sections[current]; !ok {
				sections[current] = map[string]string{}
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || current == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		sections[current][key] = value
	}

	cfg := SpaceConfig{
		FofaNum:   3000,
		QuakeNum:  1000,
		HunterNum: 1000,
	}
	if sec, ok := sections["fofa api"]; ok {
		cfg.FofaEmail = sec["email"]
		cfg.FofaKey = sec["key"]
		if n, err := strconv.Atoi(sec["fofa_nums"]); err == nil && n > 0 {
			cfg.FofaNum = n
		}
	}
	if sec, ok := sections["quake api"]; ok {
		cfg.QuakeToken = sec["x-quaketoken"]
	}
	if sec, ok := sections["quake nums"]; ok {
		if n, err := strconv.Atoi(sec["quake_nums"]); err == nil && n > 0 {
			cfg.QuakeNum = n
		}
	}
	if sec, ok := sections["hunter api"]; ok {
		cfg.HunterKey = sec["api-key"]
	}
	if sec, ok := sections["hunter nums"]; ok {
		if n, err := strconv.Atoi(sec["hunter_nums"]); err == nil && n > 0 {
			cfg.HunterNum = n
		}
	}
	if sec, ok := sections["icp_query"]; ok {
		cfg.ICPQueryURL = sec["url"]
		cfg.ICPQueryToken = sec["token"]
	}
	if sec, ok := sections["riskbird"]; ok {
		cfg.RiskbirdCookie = sec["cookie"]
	}
	return cfg, nil
}

func loadSubfinderConfig(root string) (SubfinderConfig, error) {
	path := filepath.Join(root, "config", "subfinder-config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return SubfinderConfig{}, err
	}

	cfg := SubfinderConfig{Credentials: map[string][]string{}}
	current := ""
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(rawLine, " ") && !strings.HasPrefix(rawLine, "\t") && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			current = strings.TrimSpace(parts[0])
			rest := strings.TrimSpace(parts[1])
			if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
				cfg.Credentials[current] = parseInlineList(rest)
			} else if rest == "[]" {
				cfg.Credentials[current] = nil
			}
			continue
		}
		if current == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if value != "" {
				cfg.Credentials[current] = append(cfg.Credentials[current], value)
			}
		}
	}
	return cfg, nil
}

func parseInlineList(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"'`)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func (a *App) preflight(ctx context.Context) []CredentialWarning {
	warnings := make([]CredentialWarning, 0)

	if a.spaceConfig.FofaEmail == "" || a.spaceConfig.FofaKey == "" {
		warnings = append(warnings, CredentialWarning{
			Source:  "config/spaceConfig.ini:fofa",
			Message: "FOFA 邮箱或 key 为空",
		})
	} else {
		if warning := a.validateFOFA(ctx, a.spaceConfig.FofaEmail, a.spaceConfig.FofaKey, "config/spaceConfig.ini:fofa"); warning != nil {
			warnings = append(warnings, *warning)
		}
	}

	if a.spaceConfig.QuakeToken == "" {
		warnings = append(warnings, CredentialWarning{
			Source:  "config/spaceConfig.ini:quake",
			Message: "Quake token 为空",
		})
	} else {
		if warning := a.validateQuake(ctx, a.spaceConfig.QuakeToken, "config/spaceConfig.ini:quake"); warning != nil {
			warnings = append(warnings, *warning)
		}
	}

	if a.spaceConfig.HunterKey == "" {
		warnings = append(warnings, CredentialWarning{
			Source:  "config/spaceConfig.ini:hunter",
			Message: "Hunter API-Key 为空",
		})
	}

	if creds := a.subfinderConfig.Credentials["fofa"]; len(creds) > 0 {
		for _, cred := range creds {
			if cred == a.spaceConfig.FofaEmail+":"+a.spaceConfig.FofaKey {
				continue
			}
			email, key, ok := strings.Cut(cred, ":")
			if !ok || email == "" || key == "" {
				warnings = append(warnings, CredentialWarning{
					Source:  "config/subfinder-config.yaml:fofa",
					Message: fmt.Sprintf("凭据格式异常: %s", cred),
				})
				continue
			}
			if warning := a.validateFOFA(ctx, email, key, "config/subfinder-config.yaml:fofa"); warning != nil {
				warnings = append(warnings, *warning)
			}
		}
	}

	if creds := a.subfinderConfig.Credentials["shodan"]; len(creds) > 0 {
		for _, cred := range creds {
			if warning := a.validateShodan(ctx, cred, "config/subfinder-config.yaml:shodan"); warning != nil {
				warnings = append(warnings, *warning)
			}
		}
	}

	if creds := a.subfinderConfig.Credentials["securitytrails"]; len(creds) > 0 {
		for _, cred := range creds {
			if warning := a.validateSecurityTrails(ctx, cred, "config/subfinder-config.yaml:securitytrails"); warning != nil {
				warnings = append(warnings, *warning)
			}
		}
	}

	// 标记本轮不可用来源，避免每目标重复请求
	a.skipSources = make(map[string]bool)
	if a.spaceConfig.FofaEmail == "" || a.spaceConfig.FofaKey == "" {
		a.skipSources["fofa-subdomain"] = true
	}
	if a.spaceConfig.QuakeToken == "" {
		a.skipSources["quake-subdomain"] = true
	}
	for _, w := range warnings {
		if strings.Contains(w.Source, "fofa") {
			a.skipSources["fofa-subdomain"] = true
		}
		if strings.Contains(w.Source, "quake") {
			a.skipSources["quake-subdomain"] = true
		}
	}

	return warnings
}

func (a *App) validateFOFA(ctx context.Context, email, key, source string) *CredentialWarning {
	q := url.Values{}
	q.Set("email", email)
	q.Set("key", key)
	endpoint := "https://fofa.info/api/v1/info/my?" + q.Encode()

	var resp struct {
		Error  bool   `json:"error"`
		Errmsg string `json:"errmsg"`
		Email  string `json:"email"`
	}

	if err := a.getJSON(ctx, endpoint, nil, &resp); err != nil {
		return &CredentialWarning{Source: source, Message: fmt.Sprintf("无法验证 FOFA 凭据: %v", err)}
	}
	if resp.Error {
		msg := resp.Errmsg
		if msg == "" {
			msg = "接口返回 error=true"
		}
		return &CredentialWarning{Source: source, Message: msg}
	}
	if resp.Email == "" {
		return &CredentialWarning{Source: source, Message: "FOFA 返回异常，未识别到账户信息"}
	}
	return nil
}

func (a *App) validateQuake(ctx context.Context, token, source string) *CredentialWarning {
	reqHeaders := map[string]string{"X-QuakeToken": token}
	var resp quakeEnvelope
	if err := a.getJSON(ctx, quakeUserInfoURL, reqHeaders, &resp); err != nil {
		return &CredentialWarning{Source: source, Message: fmt.Sprintf("无法验证 Quake token: %v", err)}
	}
	if !resp.Code.IsSuccess() || quakeDataEmpty(resp.Data) {
		msg := resp.Message
		if msg == "" {
			if code := resp.Code.String(); code != "" {
				msg = fmt.Sprintf("接口返回 code=%s", code)
			} else {
				msg = "接口返回异常"
			}
		}
		return &CredentialWarning{Source: source, Message: msg}
	}
	return nil
}

func (a *App) validateShodan(ctx context.Context, key, source string) *CredentialWarning {
	key = strings.TrimSpace(key)
	if key == "" {
		return &CredentialWarning{Source: source, Message: "Shodan key 为空"}
	}
	endpoint := "https://api.shodan.io/api-info?key=" + url.QueryEscape(key)
	var payload map[string]any
	if err := a.getJSON(ctx, endpoint, nil, &payload); err != nil {
		return &CredentialWarning{Source: source, Message: fmt.Sprintf("无法验证 Shodan key: %v", err)}
	}
	if _, ok := payload["error"]; ok {
		return &CredentialWarning{Source: source, Message: fmt.Sprintf("%v", payload["error"])}
	}
	return nil
}

func (a *App) validateSecurityTrails(ctx context.Context, key, source string) *CredentialWarning {
	key = strings.TrimSpace(key)
	if key == "" {
		return &CredentialWarning{Source: source, Message: "SecurityTrails key 为空"}
	}
	var payload map[string]any
	headers := map[string]string{"APIKEY": key}
	if err := a.getJSON(ctx, "https://api.securitytrails.com/v1/ping", headers, &payload); err != nil {
		return &CredentialWarning{Source: source, Message: fmt.Sprintf("无法验证 SecurityTrails key: %v", err)}
	}
	if msg, ok := payload["message"].(string); ok && msg != "" && strings.Contains(strings.ToLower(msg), "invalid") {
		return &CredentialWarning{Source: source, Message: msg}
	}
	return nil
}

func (a *App) getJSON(ctx context.Context, endpoint string, headers map[string]string, out any) error {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}
	return nil
}

func encodeFofaQuery(query string) string {
	return base64.StdEncoding.EncodeToString([]byte(query))
}
