package doctor_test

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/kubenexis/knxvault/pkg/client"
	"github.com/kubenexis/knxvault/pkg/doctor"
)

func TestRunnerNativeBackendWithoutOpenSSLWarns(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err == nil {
		t.Skip("openssl is installed; cannot test missing-openssl warning path")
	}

	t.Setenv("KNXVAULT_PKI_BACKEND", "native")

	runner := &doctor.Runner{
		Client: client.New("http://127.0.0.1:1", ""),
		Config: doctor.Config{Addr: "http://127.0.0.1:1", PKIBackend: "native"},
	}
	report := runner.Run(context.Background())

	var found bool
	for _, check := range report.Checks {
		if check.ID == "local.openssl" {
			found = true
			if check.Status != doctor.StatusWarn {
				t.Fatalf("local.openssl status = %s, want warn", check.Status)
			}
		}
	}
	if !found {
		t.Fatal("expected local.openssl check")
	}
}

func TestRunnerNativeBackendWithOpenSSLOptional(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}

	runner := &doctor.Runner{
		Client: client.New("http://127.0.0.1:1", ""),
		Config: doctor.Config{Addr: "http://127.0.0.1:1", PKIBackend: "native"},
	}
	report := runner.Run(context.Background())

	for _, check := range report.Checks {
		if check.ID == "local.openssl" && check.Status != doctor.StatusOK {
			t.Fatalf("local.openssl status = %s, want ok", check.Status)
		}
	}
	_ = os.Getenv("KNXVAULT_PKI_BACKEND")
}
