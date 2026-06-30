// Package openssl provides a sandboxed OpenSSL CLI wrapper (LLD §4.A.1).
package openssl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ExecResult captures command output.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Wrapper runs OpenSSL in isolated temporary workspaces.
type Wrapper struct {
	binary  string
	timeout time.Duration
	breaker *Breaker
}

// New creates a Wrapper. binary defaults to "openssl" when empty.
func New(binary string, timeout time.Duration) *Wrapper {
	if binary == "" {
		binary = "openssl"
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Wrapper{
		binary:  binary,
		timeout: timeout,
		breaker: NewBreaker(3, 30*time.Second),
	}
}

// SetBreaker configures the circuit breaker used by SafeExec.
func (w *Wrapper) SetBreaker(b *Breaker) {
	w.breaker = b
}

// BreakerOpen reports whether the OpenSSL circuit breaker is open.
func (w *Wrapper) BreakerOpen() bool {
	if w.breaker == nil {
		return false
	}
	return w.breaker.Open()
}

// forbiddenArgs blocks dangerous OpenSSL flags.
var forbiddenArgs = map[string]bool{
	"-engine":        true,
	"-provider":      true,
	"-provider-path": true,
	"-rand":          true,
}

// SafeExec runs openssl with strict controls.
func (w *Wrapper) SafeExec(ctx context.Context, args []string, stdin io.Reader) (*ExecResult, error) {
	if w.breaker != nil {
		if err := w.breaker.Allow(); err != nil {
			return nil, err
		}
	}
	if err := validateArgs(args); err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "knxvault-openssl-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod temp dir: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, w.binary, args...)
	cmd.Dir = tmpDir
	cmd.Env = minimalEnv()

	if stdin != nil {
		cmd.Stdin = stdin
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			if w.breaker != nil {
				w.breaker.RecordFailure()
			}
			return nil, fmt.Errorf("openssl exec: %w", err)
		}
	}

	if exitCode != 0 {
		if w.breaker != nil {
			w.breaker.RecordFailure()
		}
	} else if w.breaker != nil {
		w.breaker.RecordSuccess()
	}

	return &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}, nil
}

// Version returns the OpenSSL version string.
func (w *Wrapper) Version(ctx context.Context) (string, error) {
	res, err := w.SafeExec(ctx, []string{"version"}, nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("openssl version failed: %s", strings.TrimSpace(res.Stderr))
	}
	return strings.TrimSpace(res.Stdout), nil
}

func validateArgs(args []string) error {
	for i, arg := range args {
		if forbiddenArgs[strings.ToLower(arg)] {
			return fmt.Errorf("forbidden openssl argument: %s", arg)
		}
		if strings.HasPrefix(arg, "-config") {
			if i+1 >= len(args) {
				return fmt.Errorf("-config requires a path")
			}
			cfg := args[i+1]
			if !filepath.IsAbs(cfg) || strings.Contains(cfg, "..") {
				return fmt.Errorf("config path must be absolute and not contain parent segments")
			}
		}
	}
	return nil
}

func minimalEnv() []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"OPENSSL_CONF=/dev/null",
	}
}
