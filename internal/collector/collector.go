//go:build linux || darwin

package collector

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"selfdiag.local/rebuild/internal/evidence"
)

type fileSpec struct{ path, kind string }
type commandSpec struct {
	kind string
	args []string
}

type boundedBuffer struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := evidence.MaxFile - len(b.data)
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	b.data = append(b.data, p...)
	return n, nil
}

func command(ctx context.Context, args []string) ([]byte, string, string) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "TZ=UTC")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	var b boundedBuffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	err := cmd.Run()
	status, detail := "collected", ""
	if err != nil {
		status = "error"
		detail = err.Error()
	}
	if errors.Is(err, exec.ErrNotFound) {
		status = "unsupported"
	}
	if ctx.Err() != nil {
		status = "timeout"
		detail = ctx.Err().Error()
	}
	if b.truncated {
		if status == "collected" {
			status = "truncated"
		}
		detail += "; command output byte limit"
	}
	return b.data, status, detail
}

func Collect(out, profile string, timeout time.Duration) error {
	return CollectWithOptions(out, Options{Profile: profile, Timeout: timeout, SourceOS: runtime.GOOS})
}
