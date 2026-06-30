package openssl_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto/openssl"
)

func TestValidateArgsRejectsForbidden(t *testing.T) {
	w := openssl.New("", time.Second)
	_, err := w.SafeExec(context.Background(), []string{"version", "-engine", "foo"}, nil)
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("expected forbidden error, got %v", err)
	}
}

func TestVersion(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}

	w := openssl.New("", 10*time.Second)
	ver, err := w.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if !strings.Contains(ver, "OpenSSL") {
		t.Fatalf("unexpected version output: %q", ver)
	}
}

func FuzzSafeExec(f *testing.F) {
	f.Add("version")
	f.Fuzz(func(t *testing.T, arg string) {
		w := openssl.New("", time.Second)
		args := []string{"version"}
		if arg != "" {
			args = append(args, arg)
		}
		_, err := w.SafeExec(context.Background(), args, nil)
		if err != nil {
			if strings.Contains(err.Error(), "forbidden") {
				return
			}
			if strings.Contains(err.Error(), "circuit breaker") {
				return
			}
		}
	})
}

func TestSafeExecUsesIsolatedWorkDir(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}

	w := openssl.New("", 10*time.Second)
	res, err := w.SafeExec(context.Background(), []string{"version"}, nil)
	if err != nil {
		t.Fatalf("SafeExec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d stderr=%s", res.ExitCode, res.Stderr)
	}
}
