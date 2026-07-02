// Package openssl provides sandboxed OpenSSL execution.
package openssl

import (
	"context"
	"io"
)

// Engine abstracts OpenSSL cryptographic operations (W31-01).
type Engine interface {
	SafeExec(ctx context.Context, args []string, stdin io.Reader) (*ExecResult, error)
	Name() string
}

// CLIEngine delegates to the OpenSSL CLI wrapper.
type CLIEngine struct {
	wrapper *Wrapper
}

// NewCLIEngine constructs a CLI-backed engine.
func NewCLIEngine(w *Wrapper) *CLIEngine {
	return &CLIEngine{wrapper: w}
}

func (e *CLIEngine) Name() string { return "cli" }

func (e *CLIEngine) SafeExec(ctx context.Context, args []string, stdin io.Reader) (*ExecResult, error) {
	if e == nil || e.wrapper == nil {
		return nil, ErrNotConfigured
	}
	return e.wrapper.SafeExec(ctx, args, stdin)
}

// ErrNotConfigured indicates the engine is unavailable.
var ErrNotConfigured = errNotConfigured("openssl engine not configured")

type errNotConfigured string

func (e errNotConfigured) Error() string { return string(e) }
