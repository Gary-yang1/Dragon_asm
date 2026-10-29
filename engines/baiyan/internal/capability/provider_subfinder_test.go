package capability

import (
	"baiyan/internal/toolrunner"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSubfinderPublishesBeforeProcessExits(t *testing.T) {
	dir := t.TempDir()
	release := filepath.Join(dir, "release")
	binary := filepath.Join(dir, "subfinder")
	script := "#!/bin/sh\nprintf 'api.example.com\\noutside.test\\n'\nwhile [ ! -f '" + release + "' ]; do sleep 0.1; done\nprintf 'last.example.com\\n'\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	runner, err := toolrunner.NewRegistry([]toolrunner.Spec{SubfinderToolSpec(binary)})
	if err != nil {
		t.Fatal(err)
	}
	provider := NewSubfinderProvider(runner)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan []string, 3)
	done := make(chan error, 1)
	go func() {
		done <- provider.DiscoverStream(ctx, "example.com", func(hosts []string) error { got <- hosts; return nil })
	}()
	select {
	case hosts := <-got:
		if len(hosts) != 1 || hosts[0] != "api.example.com" {
			t.Fatal(hosts)
		}
	case <-ctx.Done():
		t.Fatal("no early output")
	}
	select {
	case err := <-done:
		t.Fatalf("source finished before release: %v", err)
	default:
	}
	if err := os.WriteFile(release, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if hosts := <-got; len(hosts) != 1 || hosts[0] != "last.example.com" {
		t.Fatal(hosts)
	}
}
