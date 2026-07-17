// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"encoding/base64"
	"testing"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
)

func TestNewDependenciesInMemory(t *testing.T) {
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_MASTER_KEY", "")
	t.Setenv("KNXVAULT_MASTER_KEY_FILE", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	deps, err := app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDependencies() = %v", err)
	}
	if deps.AuthService == nil {
		t.Fatal("expected auth service")
	}
	if deps.CARepo == nil || deps.SecretRepo == nil {
		t.Fatal("expected in-memory repositories")
	}
}

func TestNewDependenciesEngineRegistry(t *testing.T) {
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_MASTER_KEY", testMasterKeyB64())
	t.Setenv("KNXVAULT_MASTER_KEY_FILE", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	deps, err := app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDependencies() = %v", err)
	}
	if deps.EngineRegistry == nil {
		t.Fatal("expected engine registry")
	}
	engines := deps.EngineRegistry.List()
	if len(engines) != 3 {
		t.Fatalf("engines = %v, want len 3", engines)
	}
	found := map[string]bool{}
	for _, name := range engines {
		found[name] = true
	}
	for _, want := range []string{"kv", "database", "ssh"} {
		if !found[want] {
			t.Fatalf("missing engine %q in %v", want, engines)
		}
	}
}

func testMasterKeyB64() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestNewDependenciesRequiresMasterKeyWithRaft(t *testing.T) {
	t.Setenv("KNXVAULT_RAFT_ENABLED", "true")
	t.Setenv("KNXVAULT_RAFT_NODE_ID", "1")
	t.Setenv("KNXVAULT_RAFT_INITIAL_MEMBERS", "1=127.0.0.1:63001")
	t.Setenv("KNXVAULT_MASTER_KEY", "")
	t.Setenv("KNXVAULT_MASTER_KEY_FILE", "")
	t.Setenv("KNXVAULT_UNSEAL_KEY", "dGVzdC11bnNlYWwta2V5MTIzNDU2Nzg5MDEyMzQ1Ng==")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	_, err = app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err == nil {
		t.Fatal("expected error without master key when raft enabled")
	}
}

func TestNewDependenciesServicesWired(t *testing.T) {
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_MASTER_KEY", testMasterKeyB64())
	t.Setenv("KNXVAULT_MASTER_KEY_FILE", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	deps, err := app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDependencies() = %v", err)
	}
	if deps.PKIService == nil || deps.SecretsService == nil || deps.DatabaseService == nil {
		t.Fatal("expected core services")
	}
	if deps.PolicyService == nil || deps.BackupService == nil || deps.InjectService == nil {
		t.Fatal("expected auxiliary services")
	}
	if deps.JobRunner == nil || deps.Leader == nil {
		t.Fatal("expected job runner and leader elector")
	}
}

func TestDependenciesHelpers(t *testing.T) {
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_MASTER_KEY", testMasterKeyB64())
	t.Setenv("KNXVAULT_MASTER_KEY_FILE", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	deps, err := app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDependencies() = %v", err)
	}

	if err := deps.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() = %v", err)
	}
	if deps.HAEnabled() {
		t.Fatal("expected HA disabled without raft/k8s")
	}
	if deps.RaftEnabled() {
		t.Fatal("expected raft disabled")
	}
	if !deps.IsLeader() {
		t.Fatal("expected noop elector to report leader")
	}

	deps.Close()
	deps.Close()
}
