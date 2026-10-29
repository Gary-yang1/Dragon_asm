// Package toolrunner executes pinned external binaries under fixed constraints.
//
// The engine is about to gain capabilities that no reasonable amount of Go can
// provide on its own — port sweeps, fingerprinting, directory probing. Those
// come from third-party binaries, which means the engine now runs code it did
// not write, against targets it does not own, holding secrets it must not leak.
//
// Every rule here exists because of one of those three facts:
//
//   - Only binaries registered at start-up can run, resolved to absolute paths
//     and checked for a sane mode. A tool name arriving in a job request can
//     never select an arbitrary executable.
//   - Arguments never reach a shell, and an argument that looks like a flag is
//     refused unless the tool's spec allows that exact flag. This is what stops
//     a hostile target value from turning into "--output=/app/config".
//   - The child gets an explicitly built environment, never the engine's own.
//     The engine holds the callback HMAC secret and the engine token; a
//     third-party binary has no business seeing either.
//   - Output is capped, the run is bounded by a timeout, and cancellation kills
//     the whole process group. Tools spawn helpers, and a tool that ignores
//     SIGTERM must not outlive the job that started it.
package toolrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	// ErrUnknownTool marks a request naming a binary that was not registered.
	ErrUnknownTool = errors.New("toolrunner: tool is not registered")
	// ErrFlagNotAllowed marks an argument that looks like a flag the spec does not permit.
	ErrFlagNotAllowed = errors.New("toolrunner: argument is not an allowed flag")
	// ErrInvalidArgument marks an argument the runner refuses to pass on at all.
	ErrInvalidArgument = errors.New("toolrunner: argument is not acceptable")
	// ErrInvalidSpec marks a tool registration that cannot be trusted.
	ErrInvalidSpec = errors.New("toolrunner: tool specification is invalid")
	// ErrTimeout marks a run stopped by its own deadline rather than by the tool.
	ErrTimeout = errors.New("toolrunner: tool exceeded its timeout")
	// ErrInvalidEnv marks an environment entry the runner will not forward.
	ErrInvalidEnv = errors.New("toolrunner: environment entry is not acceptable")
)

const (
	// DefaultMaxOutput bounds one stream from one run. Discovery tools are
	// expected to emit lines, not archives; anything past this is a malfunction
	// and reading it would only cost the engine memory.
	DefaultMaxOutput int64 = 8 << 20
	// DefaultTimeout applies when a request does not set one.
	DefaultTimeout = 5 * time.Minute
	// MaxTimeout is the ceiling regardless of what a caller asks for.
	MaxTimeout = 30 * time.Minute
	// killGrace is how long a cancelled process has to exit before its group is
	// killed outright.
	killGrace = 5 * time.Second
)

// envKeyPattern is intentionally strict: names outside this shape are either a
// mistake or an attempt to smuggle something past the environment allowlist.
var envKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Spec registers one external binary and the flags it may be invoked with.
type Spec struct {
	// Name is the logical name callers use. It is not a path.
	Name string
	// Path is the absolute path of the binary inside the image.
	Path string
	// AllowedFlags lists every flag this tool may receive, including the leading
	// dashes. An empty list means the tool takes positional arguments only.
	AllowedFlags []string
	// MaxOutput overrides DefaultMaxOutput for one stream of one run.
	MaxOutput int64
}

type tool struct {
	name         string
	path         string
	allowedFlags map[string]bool
	maxOutput    int64
}

// Registry holds the binaries the engine is permitted to execute.
type Registry struct {
	tools map[string]*tool
}

// NewRegistry validates every spec and returns a registry, or the first problem.
//
// Validation happens once at start-up rather than per run: a missing or
// unexpectedly writable tool should stop the engine from claiming a capability
// it cannot safely provide, not fail halfway through a customer's scan.
func NewRegistry(specs []Spec) (*Registry, error) {
	reg := &Registry{tools: make(map[string]*tool, len(specs))}
	for _, spec := range specs {
		name := strings.TrimSpace(spec.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: tool name is empty", ErrInvalidSpec)
		}
		if _, exists := reg.tools[name]; exists {
			return nil, fmt.Errorf("%w: %s is registered twice", ErrInvalidSpec, name)
		}
		path, err := validateToolPath(spec.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidSpec, name, err)
		}
		flags := make(map[string]bool, len(spec.AllowedFlags))
		for _, flag := range spec.AllowedFlags {
			flag = strings.TrimSpace(flag)
			if !strings.HasPrefix(flag, "-") {
				return nil, fmt.Errorf("%w: %s: allowed flag %q does not start with a dash", ErrInvalidSpec, name, flag)
			}
			flags[flag] = true
		}
		maxOutput := spec.MaxOutput
		if maxOutput <= 0 {
			maxOutput = DefaultMaxOutput
		}
		reg.tools[name] = &tool{name: name, path: path, allowedFlags: flags, maxOutput: maxOutput}
	}
	return reg, nil
}

func validateToolPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is empty")
	}
	if !filepath.IsAbs(path) {
		// A relative path resolves against the working directory, which a job can
		// influence. Only an absolute path names one specific file.
		return "", errors.New("path must be absolute")
	}
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("path is not usable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("path is not a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("path is not executable")
	}
	if info.Mode().Perm()&0o022 != 0 {
		// A group- or world-writable binary can be replaced by anything that gets
		// a foothold in the container, which would defeat the whole registry.
		return "", errors.New("path is writable by group or other")
	}
	return clean, nil
}

// Names lists the registered tools. Used by health reporting.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	return names
}

// Has reports whether a tool is registered.
func (r *Registry) Has(name string) bool {
	_, ok := r.tools[strings.TrimSpace(name)]
	return ok
}

// Request is one invocation.
type Request struct {
	// OnStdoutLine receives bounded output lines while the process is running.
	OnStdoutLine func(string) error
	// Tool is the registered logical name.
	Tool string
	// Args are passed verbatim to the binary. They never reach a shell.
	Args []string
	// Timeout bounds this run. Zero means DefaultTimeout; anything above
	// MaxTimeout is clamped.
	Timeout time.Duration
	// Dir is the working directory. It must be absolute when set.
	Dir string
	// Env is the complete environment for the child. The engine's own
	// environment is never inherited, so anything the tool needs must be listed
	// here explicitly.
	Env map[string]string
}

// Result is what one invocation produced.
type Result struct {
	Stdout          []byte
	Stderr          []byte
	ExitCode        int
	StdoutTruncated bool
	StderrTruncated bool
	Duration        time.Duration
}

// Run executes one registered tool under the constraints described on the
// package.
//
// A non-zero exit status is returned as a Result with ExitCode set and a nil
// error: tools routinely exit non-zero for "found nothing", and the caller is
// better placed to decide what that means than the runner is.
func (r *Registry) Run(ctx context.Context, req Request) (Result, error) {
	registered, ok := r.tools[strings.TrimSpace(req.Tool)]
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrUnknownTool, req.Tool)
	}
	if err := validateArgs(registered, req.Args); err != nil {
		return Result{}, err
	}
	env, err := buildEnv(req.Env)
	if err != nil {
		return Result{}, err
	}
	if req.Dir != "" && !filepath.IsAbs(req.Dir) {
		return Result{}, fmt.Errorf("%w: working directory must be absolute", ErrInvalidArgument)
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, registered.path, req.Args...) // #nosec G204 -- path comes from the registry, args are flag-checked above
	cmd.Dir = req.Dir
	cmd.Env = env
	// No stdin: a tool that blocks waiting for input would otherwise hold a
	// worker until the timeout expires.
	cmd.Stdin = bytes.NewReader(nil)
	stdout := &cappedBuffer{limit: registered.maxOutput}
	stderr := &cappedBuffer{limit: registered.maxOutput}
	cmd.Stdout = stdout
	var lines *lineOutput
	if req.OnStdoutLine != nil {
		lines = &lineOutput{sink: stdout, emit: req.OnStdoutLine, cancel: cancel}
		cmd.Stdout = lines
	}
	cmd.Stderr = stderr
	configureProcessGroup(cmd)
	// Cancel kills the whole group, and WaitDelay stops a child that keeps the
	// output pipes open from blocking Wait forever.
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = killGrace

	started := time.Now()
	runErr := cmd.Run()
	if lines != nil && lines.err == nil && len(lines.pending) > 0 {
		lines.err = lines.emit(string(lines.pending))
	}
	if lines != nil && lines.err != nil {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, lines.err
	}
	result := Result{
		Stdout: stdout.Bytes(), Stderr: stderr.Bytes(),
		StdoutTruncated: stdout.truncated, StderrTruncated: stderr.truncated,
		Duration: time.Since(started),
	}

	if ctxErr := ctx.Err(); errors.Is(ctxErr, context.DeadlineExceeded) {
		return result, fmt.Errorf("%w: %s after %s", ErrTimeout, registered.name, timeout)
	} else if ctxErr != nil {
		return result, ctxErr
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	if runErr != nil {
		return result, fmt.Errorf("toolrunner: %s failed to run: %w", registered.name, runErr)
	}
	return result, nil
}

func validateArgs(registered *tool, args []string) error {
	for _, arg := range args {
		if arg == "" {
			return fmt.Errorf("%w: empty argument", ErrInvalidArgument)
		}
		if strings.ContainsRune(arg, 0) {
			return fmt.Errorf("%w: argument contains a NUL byte", ErrInvalidArgument)
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		// "--flag=value" is one argument to the OS but two things to a human, so
		// the flag half is what gets checked.
		flag := arg
		if idx := strings.IndexByte(arg, '='); idx > 0 {
			flag = arg[:idx]
		}
		if !registered.allowedFlags[flag] {
			return fmt.Errorf("%w: %s does not accept %s", ErrFlagNotAllowed, registered.name, flag)
		}
	}
	return nil
}

func buildEnv(entries map[string]string) ([]string, error) {
	env := make([]string, 0, len(entries))
	for key, value := range entries {
		if !envKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("%w: %q is not a valid variable name", ErrInvalidEnv, key)
		}
		if strings.ContainsAny(value, "\x00\n") {
			return nil, fmt.Errorf("%w: %s contains a newline or NUL byte", ErrInvalidEnv, key)
		}
		env = append(env, key+"="+value)
	}
	return env, nil
}

// cappedBuffer records at most limit bytes and remembers that it stopped.
//
// Writes past the limit are discarded rather than rejected: returning an error
// would surface as a write failure on the pipe, and a tool that dies from a
// broken pipe is harder to diagnose than one whose output was simply cut.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remaining := c.limit - int64(c.buf.Len())
	if remaining <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		c.buf.Write(p[:remaining])
		c.truncated = true
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// exec serializes writes to this stream. Cancellation releases a blocked child
// when the consumer rejects a line (e.g. callback delivery failed).
type lineOutput struct {
	sink    *cappedBuffer
	emit    func(string) error
	cancel  context.CancelFunc
	pending []byte
	err     error
}

func (w *lineOutput) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	_, _ = w.sink.Write(p)
	if w.sink.truncated {
		w.err = errors.New("tool output limit exceeded")
		w.cancel()
		return 0, w.err
	}
	for _, b := range p {
		if b == '\n' {
			w.err = w.emit(strings.TrimSuffix(string(w.pending), "\r"))
			w.pending = nil
			if w.err != nil {
				w.cancel()
				return 0, w.err
			}
		} else {
			w.pending = append(w.pending, b)
			if len(w.pending) > 65536 {
				w.err = errors.New("tool output line too long")
				w.cancel()
				return 0, w.err
			}
		}
	}
	return len(p), nil
}
