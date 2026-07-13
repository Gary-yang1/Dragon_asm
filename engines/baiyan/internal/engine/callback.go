package engine

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"baiyan/internal/contract"
)

type CallbackSender struct {
	secret        string
	engineID      string
	allowedOrigin string
	client        *http.Client
	now           func() time.Time
}

func NewCallbackSender(secret, allowedOrigin string, client *http.Client) (*CallbackSender, error) {
	return newCallbackSender(secret, "", allowedOrigin, client)
}

// NewIdentityBoundCallbackSender includes the configured engine identity on
// every callback. The identity is a secret reference, never secret material.
func NewIdentityBoundCallbackSender(secret, engineID, allowedOrigin string, client *http.Client) (*CallbackSender, error) {
	engineID = strings.TrimSpace(engineID)
	if !validEngineIdentity(engineID) {
		return nil, errors.New("baiyan callback: engine identity is invalid")
	}
	return newCallbackSender(secret, engineID, allowedOrigin, client)
}

func newCallbackSender(secret, engineID, allowedOrigin string, client *http.Client) (*CallbackSender, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, errors.New("baiyan callback: secret is required")
	}
	origin, err := normalizedOrigin(allowedOrigin)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &CallbackSender{secret: secret, engineID: engineID, allowedOrigin: origin, client: &clientCopy, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *CallbackSender) Send(ctx context.Context, callbackURL string, batch contract.CallbackBatch, retryLimit int) error {
	target, err := url.Parse(strings.TrimSpace(callbackURL))
	if err != nil || target.User != nil || target.Scheme == "" || target.Host == "" {
		return errors.New("baiyan callback: invalid URL")
	}
	if originFromURL(target) != s.allowedOrigin {
		return errors.New("baiyan callback: URL origin is not allowed")
	}
	query := target.Query()
	query.Set("seq", strconv.FormatUint(batch.Seq, 10))
	target.RawQuery = query.Encode()
	raw, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if len(raw) > 4<<20 {
		return errors.New("baiyan callback: batch exceeds 4 MiB")
	}
	if retryLimit < 0 {
		retryLimit = 0
	}
	if retryLimit > 8 {
		retryLimit = 8
	}
	var lastErr error
	for attempt := 0; attempt <= retryLimit; attempt++ {
		if attempt > 0 {
			delay := 100 * time.Millisecond * time.Duration(1<<(attempt-1))
			if delay > 2*time.Second {
				delay = 2 * time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		timestamp := strconv.FormatInt(s.now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(s.secret))
		_, _ = mac.Write([]byte(timestamp))
		_, _ = mac.Write(raw)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		if s.engineID != "" {
			req.Header.Set("X-Engine-ID", s.engineID)
		}
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		closeErr := resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && closeErr == nil {
			return nil
		}
		lastErr = errors.New("baiyan callback: non-success response")
	}
	if lastErr == nil {
		lastErr = errors.New("baiyan callback: delivery failed")
	}
	return lastErr
}

func validEngineIdentity(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		if index > 0 && (r == '.' || r == '_' || r == '-' || r == ':') {
			continue
		}
		return false
	}
	return true
}

func normalizedOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("baiyan callback: invalid allowed origin")
	}
	return originFromURL(parsed), nil
}

func originFromURL(parsed *url.URL) string {
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
}
