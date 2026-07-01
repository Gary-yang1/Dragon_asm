package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
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
