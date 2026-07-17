// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
	kvncrypto "github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestAppRoleRaftBackendRoundTrip(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	cryptoSvc, err := kvncrypto.NewService(master)
	if err != nil {
		t.Fatal(err)
	}
	repo := memory.NewSecretRepository()

	store := auth.NewAppRoleStore()
	store.AttachRaftBackend(repo, cryptoSvc)
	if err := store.Register("role-a", "secret-a-value", "sub-a", []string{"pol-a"}); err != nil {
		t.Fatal(err)
	}

	// New store loads from Raft blob.
	store2 := auth.NewAppRoleStore()
	store2.AttachRaftBackend(repo, cryptoSvc)
	role, err := store2.Authenticate("role-a", "secret-a-value")
	if err != nil {
		t.Fatalf("authenticate after raft load: %v", err)
	}
	if role.Subject != "sub-a" || len(role.Policies) != 1 || role.Policies[0] != "pol-a" {
		t.Fatalf("unexpected role: %+v", role)
	}
	_ = context.Background()
}
