package toolrunner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// writeScript compiles a tiny shell script and returns its absolute path. Tests
// need a real executable because the whole point of this package is what happens
// around a real process.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the runner's process controls are Unix-specific")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tool.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return path
}

func mustRegistry(t *testing.T, specs ...Spec) *Registry {
	t.Helper()
	reg, err := NewRegistry(specs)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

func TestNewRegistryRejectsUntrustworthyTools(t *testing.T) {
	good := writeScript(t, "exit 0")

	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"empty name", Spec{Name: "", Path: good}, "tool name is empty"},
		{"relative path", Spec{Name: "t", Path: "bin/tool"}, "must be absolute"},
		{"missing file", Spec{Name: "t", Path: "/nonexistent/definitely/not/here"}, "not usable"},
		{"directory", Spec{Name: "t", Path: os.TempDir()}, "not a regular file"},
		{"flag without dash", Spec{Name: "t", Path: good, AllowedFlags: []string{"silent"}}, "does not start with a dash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRegistry([]Spec{tc.spec})
			if err == nil {
				t.Fatal("expected the registration to be refused")
			}
			if !errors.Is(err, ErrInvalidSpec) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an ErrInvalidSpec mentioning %q", err, tc.want)
			}
		})
	}

	t.Run("duplicate name", func(t *testing.T) {
		_, err := NewRegistry([]Spec{{Name: "t", Path: good}, {Name: "t", Path: good}})
		if !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("got %v, want ErrInvalidSpec", err)
		}
	})

	// A binary anyone can rewrite is not a binary you can reason about.
	t.Run("world-writable binary", func(t *testing.T) {
		path := writeScript(t, "exit 0")
		if err := os.Chmod(path, 0o777); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		_, err := NewRegistry([]Spec{{Name: "t", Path: path}})
		if !errors.Is(err, ErrInvalidSpec) || !strings.Contains(err.Error(), "writable by group or other") {
			t.Fatalf("got %v, want a refusal about writability", err)
		}
	})

	// Non-executable is the honest signal that a build stage failed to produce a
	// usable tool; starting anyway would claim a capability the engine lacks.
	t.Run("non-executable file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "data")
		if err := os.WriteFile(path, []byte("not a program"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := NewRegistry([]Spec{{Name: "t", Path: path}})
		if !errors.Is(err, ErrInvalidSpec) || !strings.Contains(err.Error(), "not executable") {
			t.Fatalf("got %v, want a refusal about executability", err)
		}
	})
}

func TestRunRejectsUnregisteredTool(t *testing.T) {
	reg := mustRegistry(t, Spec{Name: "known", Path: writeScript(t, "exit 0")})
	_, err := reg.Run(context.Background(), Request{Tool: "/bin/sh"})
	if !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("got %v, want ErrUnknownTool", err)
	}
}

// The argument rule that matters: a target value is data, and data must never be
// able to become a flag.
func TestRunRefusesFlagsOutsideTheAllowlist(t *testing.T) {
	path := writeScript(t, `printf '%s\n' "$@"`)
	reg := mustRegistry(t, Spec{Name: "probe", Path: path, AllowedFlags: []string{"-d", "--output-format"}})

	refused := []struct {
		name string
		args []string
	}{
		{"unlisted short flag", []string{"-o", "/app/config.yaml"}},
		{"unlisted long flag", []string{"--config=/etc/passwd"}},
		{"target that looks like a flag", []string{"-d", "--proxy=http://attacker.test"}},
		{"lone dash-dash-anything", []string{"--exec"}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			_, err := reg.Run(context.Background(), Request{Tool: "probe", Args: tc.args})
			if !errors.Is(err, ErrFlagNotAllowed) {
				t.Fatalf("got %v, want ErrFlagNotAllowed for %v", err, tc.args)
			}
		})
	}

	t.Run("allowed flags and plain values pass through verbatim", func(t *testing.T) {
		result, err := reg.Run(context.Background(), Request{
			Tool: "probe", Args: []string{"-d", "example.com", "--output-format=json"},
		})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		got := strings.Fields(string(result.Stdout))
		want := []string{"-d", "example.com", "--output-format=json"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("arg %d: got %q, want %q", i, got[i], want[i])
			}
		}
	})
}

func TestRunRejectsMalformedArguments(t *testing.T) {
	reg := mustRegistry(t, Spec{Name: "probe", Path: writeScript(t, "exit 0")})
	for _, args := range [][]string{{""}, {"host\x00name"}} {
		_, err := reg.Run(context.Background(), Request{Tool: "probe", Args: args})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("got %v, want ErrInvalidArgument for %q", err, args)
		}
	}
}

// The engine holds the callback HMAC secret and the engine token. A third-party
// binary must not be able to read either just by being executed.
func TestRunDoesNotInheritTheEngineEnvironment(t *testing.T) {
	t.Setenv("BAIYAN_CALLBACK_SECRET", "super-secret-value")
	t.Setenv("BAIYAN_ENGINE_TOKEN", "engine-token-value")

	path := writeScript(t, "env")
	reg := mustRegistry(t, Spec{Name: "probe", Path: path})

	result, err := reg.Run(context.Background(), Request{
		Tool: "probe", Env: map[string]string{"PATH": "/usr/bin:/bin", "TOOL_MODE": "passive"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := string(result.Stdout)
	for _, leaked := range []string{"super-secret-value", "engine-token-value", "BAIYAN_CALLBACK_SECRET"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("the child environment leaked %q", leaked)
		}
	}
	for _, expected := range []string{"TOOL_MODE=passive", "PATH=/usr/bin:/bin"} {
		if !strings.Contains(out, expected) {
			t.Fatalf("expected %q in the child environment, got:\n%s", expected, out)
		}
	}
}

func TestRunRejectsMalformedEnvironment(t *testing.T) {
	reg := mustRegistry(t, Spec{Name: "probe", Path: writeScript(t, "exit 0")})
	for _, env := range []map[string]string{
		{"lowercase": "x"},
		{"WITH-DASH": "x"},
		{"": "x"},
		{"OK": "value\nLD_PRELOAD=/tmp/evil.so"},
	} {
		_, err := reg.Run(context.Background(), Request{Tool: "probe", Env: env})
		if !errors.Is(err, ErrInvalidEnv) {
			t.Fatalf("got %v, want ErrInvalidEnv for %v", err, env)
		}
	}
}

func TestRunReportsExitCodeWithoutTreatingItAsFailure(t *testing.T) {
	reg := mustRegistry(t, Spec{Name: "probe", Path: writeScript(t, "echo out; echo err >&2; exit 3")})

	result, err := reg.Run(context.Background(), Request{Tool: "probe"})
	// "found nothing" is a non-zero exit for several discovery tools, so the
	// caller decides what it means, not the runner.
	if err != nil {
		t.Fatalf("a non-zero exit must not be a runner error, got %v", err)
	}
	if result.ExitCode != 3 {
		t.Fatalf("got exit %d, want 3", result.ExitCode)
	}
	if strings.TrimSpace(string(result.Stdout)) != "out" {
		t.Fatalf("stdout: %q", result.Stdout)
	}
	// Kept separate: a tool's diagnostics must not corrupt its parsed output.
	if strings.TrimSpace(string(result.Stderr)) != "err" {
		t.Fatalf("stderr: %q", result.Stderr)
	}
}

func TestRunCapsOutput(t *testing.T) {
	// 200 KiB of output against a 4 KiB cap.
	reg := mustRegistry(t, Spec{
		Name: "chatty", MaxOutput: 4096,
		Path: writeScript(t, `i=0; while [ $i -lt 200 ]; do printf '%01024d' 0; i=$((i+1)); done`),
	})

	result, err := reg.Run(context.Background(), Request{Tool: "chatty"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.StdoutTruncated {
		t.Fatal("expected the output to be marked truncated")
	}
	if len(result.Stdout) != 4096 {
		t.Fatalf("kept %d bytes, want exactly the 4096-byte cap", len(result.Stdout))
	}
}

func TestRunEnforcesItsTimeout(t *testing.T) {
	reg := mustRegistry(t, Spec{Name: "slow", Path: writeScript(t, "sleep 30")})

	start := time.Now()
	_, err := reg.Run(context.Background(), Request{Tool: "slow", Timeout: 300 * time.Millisecond})
	elapsed := time.Since(start)

	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("the timeout took %s to take effect", elapsed)
	}
}

// A tool that spawns helpers must not leave them running when the job is
// cancelled: an orphaned scanner keeps sending packets to a target the platform
// has stopped authorising.
func TestRunKillsTheWholeProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups are Unix-specific")
	}
	dir := t.TempDir()
	started := filepath.Join(dir, "script-started")
	marker := filepath.Join(dir, "child-still-alive")

	// The script backgrounds a helper that writes the marker well after the run
	// is cancelled, then blocks. Killing only the direct child leaves the helper
	// running and the marker appears; killing the group takes it with it.
	script := writeScript(t, `
sh -c 'sleep 3; : > `+marker+`' &
: > `+started+`
sleep 60
`)
	reg := mustRegistry(t, Spec{Name: "spawner", Path: script})

	_, err := reg.Run(context.Background(), Request{
		Tool: "spawner", Timeout: 2 * time.Second,
		Env: map[string]string{"PATH": "/usr/bin:/bin"},
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	// Without this the test would pass simply because the script never got far
	// enough to fork, which proves nothing about process groups.
	if _, statErr := os.Stat(started); statErr != nil {
		t.Fatalf("the script never reached the point of spawning a helper: %v", statErr)
	}

	// Wait past the point where a surviving helper would have written the marker.
	time.Sleep(5 * time.Second)
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("a child process outlived the cancelled run")
	} else if !os.IsNotExist(statErr) {
		t.Fatalf("stat marker: %v", statErr)
	}
}

func TestRunClampsTimeoutToTheCeiling(t *testing.T) {
	reg := mustRegistry(t, Spec{Name: "quick", Path: writeScript(t, "exit 0")})
	// The clamp is not observable through a fast run, so this only asserts the
	// request is accepted; MaxTimeout is enforced in Run before the deadline is set.
	if _, err := reg.Run(context.Background(), Request{Tool: "quick", Timeout: 10 * time.Hour}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRunRejectsRelativeWorkingDirectory(t *testing.T) {
	reg := mustRegistry(t, Spec{Name: "probe", Path: writeScript(t, "exit 0")})
	_, err := reg.Run(context.Background(), Request{Tool: "probe", Dir: "jobs/17"})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v, want ErrInvalidArgument", err)
	}
}

func TestRunHonoursCallerCancellation(t *testing.T) {
	reg := mustRegistry(t, Spec{Name: "slow", Path: writeScript(t, "sleep 30")})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	_, err := reg.Run(ctx, Request{Tool: "slow", Timeout: time.Minute})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

// Guards the promise the package documentation makes: no shell is involved, so
// shell metacharacters in a target are inert.
func TestRunDoesNotUseAShell(t *testing.T) {
	path := writeScript(t, `printf '%s' "$1"`)
	reg := mustRegistry(t, Spec{Name: "echoer", Path: path})

	injected := "example.com; touch /tmp/pwned"
	result, err := reg.Run(context.Background(), Request{Tool: "echoer", Args: []string{injected}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(result.Stdout) != injected {
		t.Fatalf("got %q, want the argument passed through untouched", result.Stdout)
	}
}

func TestRegistryReportsWhatIsAvailable(t *testing.T) {
	reg := mustRegistry(t,
		Spec{Name: "a", Path: writeScript(t, "exit 0")},
		Spec{Name: "b", Path: writeScript(t, "exit 0")},
	)
	if !reg.Has("a") || !reg.Has("b") || reg.Has("c") {
		t.Fatal("Has does not reflect the registered set")
	}
	if len(reg.Names()) != 2 {
		t.Fatalf("Names returned %v", reg.Names())
	}
}

// An empty registry is the normal state for a deployment that enables no active
// capabilities, and it must be usable rather than a start-up error.
func TestEmptyRegistryIsValidAndRunsNothing(t *testing.T) {
	reg, err := NewRegistry(nil)
	if err != nil {
		t.Fatalf("NewRegistry(nil): %v", err)
	}
	if len(reg.Names()) != 0 {
		t.Fatalf("expected no tools, got %v", reg.Names())
	}
	if _, err := reg.Run(context.Background(), Request{Tool: "anything"}); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("got %v, want ErrUnknownTool", err)
	}
}
