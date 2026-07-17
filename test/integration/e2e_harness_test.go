// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	e2eRootToken = "e2e-root-token"
	e2eLogLevel  = "error"
)

var (
	e2eBinsOnce   sync.Once
	e2eServerBin  string
	e2eCLIBin     string
	e2eBinsErr    error
	e2eBuildCache string
)

// daemonEnv runs knxvault serve as a local daemon and drives knxvault-cli against it.
type daemonEnv struct {
	t        *testing.T
	workDir  string
	httpAddr string
	baseURL  string
	token    string

	serverBin string
	cliBin    string
	serverCmd *exec.Cmd
}

func startDaemon(t *testing.T, extraEnv ...string) *daemonEnv {
	t.Helper()

	serverBin, cliBin := e2eBins(t)
	workDir := t.TempDir()

	env := &daemonEnv{
		t:         t,
		workDir:   workDir,
		httpAddr:  freeTCPAddr(t),
		token:     e2eRootToken,
		serverBin: serverBin,
		cliBin:    cliBin,
	}
	env.baseURL = "http://" + env.httpAddr

	serverEnv := append(os.Environ(),
		"KNXVAULT_HTTP_ADDR="+env.httpAddr,
		"KNXVAULT_LOG_LEVEL="+e2eLogLevel,
		"KNXVAULT_MASTER_KEY="+e2eMasterKey(),
		"KNXVAULT_LAB_UNSEAL_EQUALS_MASTER=true",
		"KNXVAULT_ROOT_TOKEN="+e2eRootToken,
		"KNXVAULT_RAFT_ENABLED=false",
	)
	serverEnv = append(serverEnv, extraEnv...)

	env.serverCmd = exec.Command(env.serverBin, "serve")
	env.serverCmd.Env = serverEnv
	env.serverCmd.Dir = workDir
	stderr, err := env.serverCmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe() = %v", err)
	}
	if err := env.serverCmd.Start(); err != nil {
		t.Fatalf("start knxvault serve: %v", err)
	}

	t.Cleanup(func() {
		stopDaemon(env.serverCmd, stderr)
	})

	waitDaemonReady(t, env.baseURL, 15*time.Second, stderr)
	// Crypto always installs a seal (unseal key or master-key fallback); unseal for data-plane E2E.
	unsealDaemon(t, env.baseURL, e2eMasterKey())
	return env
}

func startDaemonWithConfig(t *testing.T, httpAddr string) *daemonEnv {
	t.Helper()

	serverBin, cliBin := e2eBins(t)
	workDir := t.TempDir()
	configPath := filepath.Join(workDir, "knxvault.conf")
	configBody := fmt.Sprintf(`---
http_addr: "%s"
log_level: error
`, httpAddr)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("WriteFile(config) = %v", err)
	}

	env := &daemonEnv{
		t:         t,
		workDir:   workDir,
		httpAddr:  httpAddr,
		baseURL:   "http://" + httpAddr,
		token:     e2eRootToken,
		serverBin: serverBin,
		cliBin:    cliBin,
	}

	serverEnv := append(os.Environ(),
		"KNXVAULT_MASTER_KEY="+e2eMasterKey(),
		"KNXVAULT_LAB_UNSEAL_EQUALS_MASTER=true",
		"KNXVAULT_ROOT_TOKEN="+e2eRootToken,
		"KNXVAULT_RAFT_ENABLED=false",
	)
	env.serverCmd = exec.Command(env.serverBin, "-c", configPath, "serve")
	env.serverCmd.Env = serverEnv
	env.serverCmd.Dir = workDir
	stderr, err := env.serverCmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe() = %v", err)
	}
	if err := env.serverCmd.Start(); err != nil {
		t.Fatalf("start knxvault serve -c: %v", err)
	}
	t.Cleanup(func() {
		stopDaemon(env.serverCmd, stderr)
	})

	waitDaemonReady(t, env.baseURL, 15*time.Second, stderr)
	unsealDaemon(t, env.baseURL, e2eMasterKey())
	return env
}

// unsealDaemon presents the base64 unseal key (raw-key encoding) so sealed vaults accept writes.
func unsealDaemon(t *testing.T, baseURL, keyB64 string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"key": keyB64})
	if err != nil {
		t.Fatalf("marshal unseal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/sys/unseal", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unseal request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("unseal status=%d body=%s", resp.StatusCode, raw)
	}
}

func (e *daemonEnv) runCLI(args ...string) []byte {
	e.t.Helper()
	return e.runCLIEnv(nil, args...)
}

// runCLIWithStderr runs the CLI and returns stdout and stderr separately (stdout stays JSON-clean).
func (e *daemonEnv) runCLIWithStderr(args ...string) (stdout []byte, stderr string) {
	e.t.Helper()
	return e.runCLIEnvWithStderr(nil, args...)
}

func (e *daemonEnv) runCLIEnv(extraEnv []string, args ...string) []byte {
	e.t.Helper()
	out, _ := e.runCLIEnvWithStderr(extraEnv, args...)
	return out
}

func (e *daemonEnv) runCLIEnvWithStderr(extraEnv []string, args ...string) (stdout []byte, stderr string) {
	e.t.Helper()
	cmd := exec.Command(e.cliBin, args...)
	env := append(os.Environ(), extraEnv...)
	if !envContains(env, "KNXVAULT_ADDR=") {
		env = append(env, "KNXVAULT_ADDR="+e.baseURL)
	}
	if !envContains(env, "KNXVAULT_TOKEN=") {
		env = append(env, "KNXVAULT_TOKEN="+e.token)
	}
	cmd.Env = env
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	out, err := cmd.Output()
	if err != nil {
		e.t.Fatalf("knxvault-cli %s: %v\nstderr: %s", strings.Join(args, " "), err, stderrBuf.String())
	}
	return out, stderrBuf.String()
}

func e2eBins(t *testing.T) (serverBin, cliBin string) {
	t.Helper()
	e2eBinsOnce.Do(func() {
		modRoot, err := moduleRoot()
		if err != nil {
			e2eBinsErr = err
			return
		}
		// Always build into build/e2e-bins so e2e never reuses a stale make build/bin
		// artifact after source changes (W78 allowed-domains flags, etc.).
		// GOCACHE stays under the module tree (not /tmp).
		cacheDir := filepath.Join(modRoot, "build", "e2e-gocache")
		binDir := filepath.Join(modRoot, "build", "e2e-bins")
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			e2eBinsErr = err
			return
		}
		if err := os.MkdirAll(binDir, 0o755); err != nil {
			e2eBinsErr = err
			return
		}
		e2eBuildCache = cacheDir
		e2eServerBin = filepath.Join(binDir, "knxvault")
		e2eCLIBin = filepath.Join(binDir, "knxvault-cli")
		if err := buildBinary(modRoot, "./cmd/knxvault", e2eServerBin); err != nil {
			e2eBinsErr = err
			return
		}
		if err := buildBinary(modRoot, "./cmd/knxvault-cli", e2eCLIBin); err != nil {
			e2eBinsErr = err
		}
	})
	if e2eBinsErr != nil {
		t.Fatalf("build e2e binaries: %v", e2eBinsErr)
	}
	return e2eServerBin, e2eCLIBin
}

func moduleRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	mod := strings.TrimSpace(string(out))
	if mod == "" || mod == "/dev/null" {
		return "", fmt.Errorf("could not resolve module root from GOMOD")
	}
	return filepath.Dir(mod), nil
}

func envContains(env []string, prefix string) bool {
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return true
		}
	}
	return false
}

func buildBinary(modRoot, pkg, outPath string) error {
	cmd := exec.Command("go", "build", "-o", outPath, pkg)
	cmd.Dir = modRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if e2eBuildCache != "" {
		cmd.Env = append(cmd.Env, "GOCACHE="+e2eBuildCache)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, out)
	}
	return nil
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func e2eMasterKey() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func waitDaemonReady(t *testing.T, baseURL string, timeout time.Duration, stderr io.Reader) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{Timeout: 2 * time.Second}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			logs := drainStderr(stderr)
			t.Fatalf("daemon not ready at %s: %v\nserver stderr:\n%s", baseURL, lastErr, logs)
		case <-ticker.C:
			resp, err := client.Get(baseURL + "/health")
			if err != nil {
				lastErr = err
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("health status %d", resp.StatusCode)
		}
	}
}

func stopDaemon(cmd *exec.Cmd, stderr io.Reader) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	_, _ = io.Copy(io.Discard, stderr)
}

func drainStderr(r io.Reader) string {
	if r == nil {
		return ""
	}
	b, _ := io.ReadAll(r)
	return string(b)
}

func parseCLIJSON(t *testing.T, out []byte, dest any) {
	t.Helper()
	if err := json.Unmarshal(out, dest); err != nil {
		t.Fatalf("decode cli json: %v\nraw: %s", err, out)
	}
}
