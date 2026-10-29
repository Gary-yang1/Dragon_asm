package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAsynqLoggerMessage confirms asynq's print-style variadic args are emitted
// as the structured-log message (collapsed via fmt.Sprint), not as broken,
// unpaired slog attributes. Regression guard for the asynq adapter.
func TestAsynqLoggerMessage(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	al := &asynqLogger{l}

	cases := []struct {
		call func()
		want string
	}{
		{func() { al.Debug("Scheduler starting") }, "Scheduler starting"},
		{func() { al.Info("queue ", "default", " drained") }, "queue default drained"},
		{func() { al.Warn("retry budget exhausted") }, "retry budget exhausted"},
		{func() { al.Error("handler panic") }, "handler panic"},
	}

	for _, c := range cases {
		buf.Reset()
		c.call()
		var rec struct {
			Msg string `json:"msg"`
		}
		if err := json.NewDecoder(&buf).Decode(&rec); err != nil {
			t.Fatalf("decode: %v (buf=%q)", err, buf.String())
		}
		if rec.Msg != c.want {
			t.Errorf("msg = %q, want %q", rec.Msg, c.want)
		}
	}
}

func TestConfiguredActiveDispatchPolicy(t *testing.T) {
	t.Setenv("DISCOVERY_ACTIVE_DISPATCH_ENABLED", "")
	t.Setenv("DISCOVERY_ACTIVE_REQUIRE_APPROVAL", "")
	t.Setenv("DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP", "")
	defaults := configuredActiveDispatchPolicy()
	assert.False(t, defaults.Enabled)
	assert.True(t, defaults.RequireApproval)
	assert.True(t, defaults.RequireOwnership)

	t.Setenv("DISCOVERY_ACTIVE_DISPATCH_ENABLED", "true")
	t.Setenv("DISCOVERY_ACTIVE_REQUIRE_APPROVAL", "false")
	t.Setenv("DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP", "false")
	opened := configuredActiveDispatchPolicy()
	assert.True(t, opened.Enabled)
	assert.False(t, opened.RequireApproval)
	assert.False(t, opened.RequireOwnership)
}
