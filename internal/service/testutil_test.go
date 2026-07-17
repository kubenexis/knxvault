// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"testing"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func testCrypto(t *testing.T) *crypto.Service {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	svc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	return svc
}

func testAudit() *auditsvc.Service {
	return auditsvc.NewService(memory.NewAuditRepository())
}

func testBackupRepos() backup.Repos {
	return backup.Repos{
		CA:         memory.NewCARepository(),
		Secret:     memory.NewSecretRepository(),
		Revoke:     memory.NewRevocationRepository(),
		Lease:      memory.NewLeaseRepository(),
		Policy:     memory.NewPolicyRepository(),
		Role:       memory.NewRoleRepository(),
		IssuedCert: memory.NewIssuedCertRepository(),
	}
}
