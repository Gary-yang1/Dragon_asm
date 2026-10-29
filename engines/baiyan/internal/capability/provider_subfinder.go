package capability

import (
	"baiyan/internal/toolrunner"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type SubfinderProvider struct {
	runner *toolrunner.Registry
	rate   int
}

func NewSubfinderProvider(runner *toolrunner.Registry) *SubfinderProvider {
	return &SubfinderProvider{runner: runner, rate: 10}
}
func (p *SubfinderProvider) WithRateLimit(rate int) PassiveProvider {
	copy := *p
	copy.rate = min(10, rate)
	if copy.rate < 1 {
		copy.rate = 1
	}
	return &copy
}

func SubfinderToolSpec(path string) toolrunner.Spec {
	return toolrunner.Spec{Name: "subfinder", Path: path, AllowedFlags: []string{"-d", "-silent", "-all", "-timeout", "-max-time", "-rl"}}
}
func (p *SubfinderProvider) Name() string { return "subfinder" }
func (p *SubfinderProvider) Discover(ctx context.Context, root string) ([]string, error) {
	var out []string
	err := p.DiscoverStream(ctx, root, func(v []string) error { out = append(out, v...); return nil })
	return out, err
}
func (p *SubfinderProvider) DiscoverStream(ctx context.Context, root string, emit func([]string) error) error {
	root = normalizeDomain(root)
	if root == "" {
		return errors.New("invalid subfinder root")
	}
	dir, err := os.MkdirTemp("", "baiyan-subfinder-")
	if err != nil {
		return errors.New("subfinder workspace unavailable")
	}
	defer os.RemoveAll(dir)
	// Isolate HOME and config: never pass callback credentials to a subprocess.

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	lines := make(chan string, 64)
	done := make(chan error, 1)
	stopped := make(chan struct{})
	defer func() { cancel(); <-stopped }()
	go func() {
		defer close(stopped)
		result, err := p.runner.Run(ctx, toolrunner.Request{Tool: "subfinder", Args: []string{"-d", root, "-all", "-silent", "-timeout", "10", "-max-time", "5", "-rl", strconv.Itoa(p.rate)}, Dir: dir, Env: map[string]string{"HOME": dir, "XDG_CONFIG_HOME": dir}, Timeout: 5 * time.Minute, OnStdoutLine: func(line string) error {
			host := normalizeDomain(strings.TrimSpace(line))
			if host == "" || !withinRoot(host, root) {
				return nil
			}
			select {
			case lines <- host:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}})
		close(lines)
		if err != nil || result.ExitCode != 0 || result.StdoutTruncated {
			done <- errors.New("subfinder did not complete")
		} else {
			done <- nil
		}
	}()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	pending := []string{}
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		err := emit(pending)
		pending = nil
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := flush(); err != nil {
				return err
			}
		case host, ok := <-lines:
			if !ok {
				if err := flush(); err != nil {
					return err
				}
				return <-done
			}
			pending = append(pending, host)
			if len(pending) >= 50 {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
}
