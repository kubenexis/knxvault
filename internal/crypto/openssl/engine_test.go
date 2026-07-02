package openssl_test

import (
	"context"
	"io"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/openssl"
)

type mockEngine struct{}

func (m *mockEngine) Name() string { return "mock" }
func (m *mockEngine) SafeExec(ctx context.Context, args []string, stdin io.Reader) (*openssl.ExecResult, error) {
	_ = ctx
	_ = args
	_ = stdin
	return &openssl.ExecResult{Stdout: "ok"}, nil
}

func TestEngineInterface(t *testing.T) {
	var e openssl.Engine = &mockEngine{}
	if e.Name() != "mock" {
		t.Fatal("unexpected name")
	}
	res, err := e.SafeExec(context.Background(), []string{"version"}, nil)
	if err != nil || res.Stdout != "ok" {
		t.Fatalf("SafeExec() stdout = %q, err = %v", res.Stdout, err)
	}
}
