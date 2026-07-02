package openssl

import (
	"context"
	"io"
	"os"
)

// PKCS11Config configures optional HSM integration (W31-02).
type PKCS11Config struct {
	ModulePath string
	Slot       string
	PIN        string
}

// PKCS11Engine is a stub engine for SoftHSM/PKCS#11 integration.
type PKCS11Engine struct {
	cfg PKCS11Config
}

// NewPKCS11Engine constructs a PKCS#11 stub engine.
func NewPKCS11Engine(cfg PKCS11Config) *PKCS11Engine {
	return &PKCS11Engine{cfg: cfg}
}

func (e *PKCS11Engine) Name() string { return "pkcs11" }

func (e *PKCS11Engine) SafeExec(ctx context.Context, args []string, stdin io.Reader) (*ExecResult, error) {
	if e == nil || e.cfg.ModulePath == "" {
		return nil, ErrNotConfigured
	}
	if _, err := os.Stat(e.cfg.ModulePath); err != nil {
		return nil, err
	}
	_ = ctx
	_ = args
	_ = stdin
	return &ExecResult{Stdout: "pkcs11-stub"}, nil
}
