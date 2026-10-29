//go:build !unix

package toolrunner

import "os/exec"

// Process groups are a Unix concept. The engine ships in a Linux container; this
// exists so the package still builds for local tooling on other platforms, and
// deliberately offers weaker cleanup rather than pretending to be equivalent.
func configureProcessGroup(*exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
