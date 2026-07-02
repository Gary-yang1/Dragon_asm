package audit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

func TestRedactTopLevelSensitiveKeys(t *testing.T) {
	input := map[string]any{
		"Authorization": "Bearer tok123",
		"username":      "alice",
	}
	got, ok := audit.Redact(input).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", got["Authorization"])
	assert.Equal(t, "alice", got["username"])
}

func TestRedactCaseInsensitive(t *testing.T) {
	cases := map[string]any{
		"PASSWORD": "hunter2",
		"Token":    "tok",
		"API_KEY":  "key123",
		"SECRET":   "s3cr3t",
		"Cookie":   "sess=abc",
	}
	got, ok := audit.Redact(cases).(map[string]any)
	require.True(t, ok)
	for k := range cases {
		assert.Equal(t, "[REDACTED]", got[k], "key %q should be redacted", k)
	}
}

func TestRedactNestedMap(t *testing.T) {
	input := map[string]any{
		"user": "alice",
		"credentials": map[string]any{
			"password": "s3cr3t",
			"role":     "admin",
		},
	}
	got, ok := audit.Redact(input).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "alice", got["user"])
	creds, ok := got["credentials"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", creds["password"])
	assert.Equal(t, "admin", creds["role"])
}

func TestRedactSliceOfMaps(t *testing.T) {
	input := []any{
		map[string]any{"secret": "abc", "id": 1},
		map[string]any{"name": "bob"},
	}
	got, ok := audit.Redact(input).([]any)
	require.True(t, ok)
	first, ok := got[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", first["secret"])
	assert.Equal(t, 1, first["id"])
	second, ok := got[1].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "bob", second["name"])
}

func TestRedactDeeplyNested(t *testing.T) {
	input := map[string]any{
		"request": map[string]any{
			"headers": map[string]any{
				"Authorization": "Bearer xyz",
				"Content-Type":  "application/json",
			},
		},
	}
	got := audit.Redact(input).(map[string]any)
	headers := got["request"].(map[string]any)["headers"].(map[string]any)
	assert.Equal(t, "[REDACTED]", headers["Authorization"])
	assert.Equal(t, "application/json", headers["Content-Type"])
}

func TestRedactNilPassthrough(t *testing.T) {
	assert.Nil(t, audit.Redact(nil))
}

func TestRedactPrimitivePassthrough(t *testing.T) {
	assert.Equal(t, "hello", audit.Redact("hello"))
	assert.Equal(t, 42, audit.Redact(42))
	assert.Equal(t, true, audit.Redact(true))
}

func TestRedactDoesNotMutateInput(t *testing.T) {
	input := map[string]any{"password": "original"}
	_ = audit.Redact(input)
	assert.Equal(t, "original", input["password"], "Redact must not modify the input map")
}

// --- Blocking issue 1: struct payloads must not leak sensitive fields ---

func TestRedactStructWithSensitiveFields(t *testing.T) {
	type creds struct {
		Password string `json:"password"`
		Token    string `json:"token"`
		Secret   string `json:"secret"`
		Username string `json:"username"`
	}
	got, ok := audit.Redact(creds{
		Password: "hunter2",
		Token:    "tok123",
		Secret:   "s3cr3t",
		Username: "alice",
	}).(map[string]any)
	require.True(t, ok, "struct should be converted to map[string]any")
	assert.Equal(t, "[REDACTED]", got["password"])
	assert.Equal(t, "[REDACTED]", got["token"])
	assert.Equal(t, "[REDACTED]", got["secret"])
	assert.Equal(t, "alice", got["username"])
}

func TestRedactStructFallsBackToFieldName(t *testing.T) {
	// No json tag: field name is used as the key.
	type noTag struct {
		Password string
		Name     string
	}
	got, ok := audit.Redact(noTag{Password: "pw", Name: "bob"}).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", got["Password"])
	assert.Equal(t, "bob", got["Name"])
}

func TestRedactStructNestedSensitiveField(t *testing.T) {
	type inner struct {
		Token string `json:"token"`
		Role  string `json:"role"`
	}
	type outer struct {
		Auth inner  `json:"auth"`
		User string `json:"user"`
	}
	got, ok := audit.Redact(outer{
		Auth: inner{Token: "abc", Role: "admin"},
		User: "alice",
	}).(map[string]any)
	require.True(t, ok)
	auth, ok := got["auth"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", auth["token"])
	assert.Equal(t, "admin", auth["role"])
	assert.Equal(t, "alice", got["user"])
}

// --- Blocking issue 2: map[string]string and other typed maps must be handled ---

func TestRedactMapStringString(t *testing.T) {
	input := map[string]string{
		"password": "hunter2",
		"username": "alice",
	}
	got, ok := audit.Redact(input).(map[string]any)
	require.True(t, ok, "map[string]string should be converted to map[string]any")
	assert.Equal(t, "[REDACTED]", got["password"])
	assert.Equal(t, "alice", got["username"])
}

func TestRedactNestedTypedMap(t *testing.T) {
	// A map[string]string nested inside a map[string]any.
	input := map[string]any{
		"headers": map[string]string{
			"Authorization": "Bearer tok",
			"Content-Type":  "application/json",
		},
	}
	got, ok := audit.Redact(input).(map[string]any)
	require.True(t, ok)
	headers, ok := got["headers"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", headers["Authorization"])
	assert.Equal(t, "application/json", headers["Content-Type"])
}

func TestRedactTypedSlice(t *testing.T) {
	input := []string{"hello", "world"}
	got, ok := audit.Redact(input).([]any)
	require.True(t, ok)
	assert.Equal(t, "hello", got[0])
	assert.Equal(t, "world", got[1])
}

// --- Token variant tests (access_token, refresh_token, apiKey, API_KEY) ---

func TestRedactAccessTokenAndRefreshToken(t *testing.T) {
	input := map[string]any{
		"access_token":  "acc-secret",
		"refresh_token": "ref-secret",
		"user_id":       "u42",
	}
	got, ok := audit.Redact(input).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", got["access_token"])
	assert.Equal(t, "[REDACTED]", got["refresh_token"])
	assert.Equal(t, "u42", got["user_id"])
}

func TestRedactMapStringStringRefreshToken(t *testing.T) {
	input := map[string]string{
		"refresh_token": "ref-tok",
		"scope":         "read",
	}
	got, ok := audit.Redact(input).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", got["refresh_token"])
	assert.Equal(t, "read", got["scope"])
}

func TestRedactStructAPIKey(t *testing.T) {
	type creds struct {
		APIKey string `json:"apiKey"`
		Name   string `json:"name"`
	}
	got, ok := audit.Redact(creds{APIKey: "ak-secret", Name: "prod"}).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", got["apiKey"])
	assert.Equal(t, "prod", got["name"])
}

func TestRedactStructAccessTokenTag(t *testing.T) {
	type tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	got, ok := audit.Redact(tokenResp{AccessToken: "at-secret", ExpiresIn: 3600}).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", got["access_token"])
	assert.Equal(t, 3600, got["expires_in"])
}
