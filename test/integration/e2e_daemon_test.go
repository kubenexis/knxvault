// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestE2EDaemonCLIWorkflow(t *testing.T) {
	env := startDaemon(t)

	// Liveness and readiness via CLI (--addr / --token flags).
	var health struct {
		Status string `json:"status"`
	}
	parseCLIJSON(t, env.runCLI("--addr", env.baseURL, "--token", env.token, "health"), &health)
	if health.Status != "healthy" {
		t.Fatalf("health status = %q, want healthy", health.Status)
	}

	var ready struct {
		Status string `json:"status"`
	}
	parseCLIJSON(t, env.runCLI("status"), &ready)
	if ready.Status != "ready" {
		t.Fatalf("ready status = %q, want ready", ready.Status)
	}

	var doctorReport struct {
		Healthy bool `json:"healthy"`
		Fail    int  `json:"fail"`
	}
	parseCLIJSON(t, env.runCLI("doctor", "--json"), &doctorReport)
	if !doctorReport.Healthy || doctorReport.Fail != 0 {
		t.Fatalf("doctor report = %+v, want healthy with no failures", doctorReport)
	}

	// Create self-signed root CA.
	const caName = "e2e-root"
	var rootCA struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		CertPEM string `json:"cert_pem"`
		Serial  string `json:"serial"`
	}
	parseCLIJSON(t, env.runCLI(
		"pki", "root",
		"--name", caName,
		"--common-name", "KNXVault E2E Root CA",
		"--ttl", "8760h",
		"--key-bits", "2048",
		"--allowed-domains", "example.com",
		"--allow-subdomains",
	), &rootCA)
	if rootCA.ID == "" || rootCA.CertPEM == "" {
		t.Fatalf("root CA response incomplete: %+v", rootCA)
	}
	if rootCA.Name != caName {
		t.Fatalf("root CA name = %q, want %q", rootCA.Name, caName)
	}

	// Issue leaf certificate signed by the root CA (role = CA name).
	var leaf struct {
		CertPEM       string `json:"cert_pem"`
		PrivateKeyPEM string `json:"private_key_pem"`
		Serial        string `json:"serial"`
		ExpiresAt     string `json:"expires_at"`
	}
	parseCLIJSON(t, env.runCLI(
		"pki", "issue",
		"--role", caName,
		"--common-name", "e2e.example.com",
		"--dns", "e2e.example.com",
		"--ttl", "720h",
	), &leaf)
	if leaf.CertPEM == "" || leaf.PrivateKeyPEM == "" || leaf.Serial == "" {
		t.Fatalf("leaf cert response incomplete: %+v", leaf)
	}
	if !strings.Contains(leaf.CertPEM, "BEGIN CERTIFICATE") {
		t.Fatal("leaf cert_pem missing PEM header")
	}

	// Write and read a KV credential (secret).
	const secretPath = "app/e2e-credential"
	const secretValue = "e2e-integration-secret"
	env.runCLI("kv", "put", secretPath, "password="+secretValue)

	var secret struct {
		Data map[string]any `json:"data"`
	}
	parseCLIJSON(t, env.runCLI("kv", "get", secretPath, "--show-secrets"), &secret)
	got, _ := secret.Data["password"].(string)
	if got != secretValue {
		t.Fatalf("secret password = %q, want %q (data=%v)", got, secretValue, secret.Data)
	}

	// Default kv get redacts values and hints on stderr.
	var redacted struct {
		Data map[string]any `json:"data"`
	}
	stdout, stderr := env.runCLIWithStderr("kv", "get", secretPath)
	parseCLIJSON(t, stdout, &redacted)
	if redacted.Data["password"] != "[REDACTED]" {
		t.Fatalf("redacted password = %v, want [REDACTED]", redacted.Data["password"])
	}
	if !strings.Contains(stderr, "--show-secrets") {
		t.Fatalf("stderr missing redaction hint: %q", stderr)
	}
}

func TestE2EDaemonCLIAddrFromEnv(t *testing.T) {
	env := startDaemon(t)

	// Only env vars — no --addr/--token flags on CLI.
	out := env.runCLIEnv([]string{
		"KNXVAULT_ADDR=" + env.baseURL,
		"KNXVAULT_TOKEN=" + env.token,
	}, "health")

	var health map[string]any
	if err := json.Unmarshal(out, &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health["status"] != "healthy" {
		t.Fatalf("health = %v", health)
	}

	env.runCLIEnv([]string{
		"KNXVAULT_ADDR=" + env.baseURL,
		"KNXVAULT_TOKEN=" + env.token,
	}, "kv", "put", "env/test", "token=from-env")
	parseCLIJSON(t, env.runCLIEnv([]string{
		"KNXVAULT_ADDR=" + env.baseURL,
		"KNXVAULT_TOKEN=" + env.token,
	}, "kv", "get", "env/test", "--show-secrets"), &struct {
		Data map[string]any `json:"data"`
	}{})
}

func TestE2EDaemonWithConfigFile(t *testing.T) {
	env := startDaemonWithConfig(t, freeTCPAddr(t))

	env.runCLI("health")

	env.runCLI(
		"pki", "root",
		"--name", "cfg-root",
		"--common-name", "Config File Root",
		"--ttl", "8760h",
	)
	env.runCLI("kv", "put", "cfg/secret", "key=config-file-value")
	var secret struct {
		Data map[string]any `json:"data"`
	}
	parseCLIJSON(t, env.runCLI("kv", "get", "cfg/secret", "--show-secrets"), &secret)
	if secret.Data["key"] != "config-file-value" {
		t.Fatalf("data = %v", secret.Data)
	}
}
