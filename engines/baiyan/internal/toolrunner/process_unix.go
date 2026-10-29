//go:build unix

package toolrunner

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group.
//
// Without this, killing the child leaves anything it spawned running: several
// discovery tools shell out to helpers, and an orphaned scanner keeps sending
// packets long after the job that authorised it is gone.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup terminates the child and everything it started.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	// A negative PID addresses the whole group. If the group is somehow gone,
	// fall back to the single process so cancellation still means something.
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}
