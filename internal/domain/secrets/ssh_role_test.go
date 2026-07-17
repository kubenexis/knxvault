// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestSSHRoleValidateAndAllowedUser(t *testing.T) {
	role := &secrets.SSHRole{
		Name:        "ops",
		TTLSeconds:  3600,
		CAKeyPath:   "ssh/ca/root",
		DefaultUser: "deploy",
	}
	if err := role.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if !role.AllowedUser("deploy") {
		t.Fatal("expected default user allowed")
	}
	if role.AllowedUser("root") {
		t.Fatal("expected root denied")
	}

	role = &secrets.SSHRole{
		Name:         "jump",
		TTLSeconds:   600,
		CAKeyPath:    "ssh/ca/root",
		AllowedUsers: []string{"alice", "bob"},
	}
	if err := role.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if !role.AllowedUser("alice") || role.AllowedUser("eve") {
		t.Fatal("allowed_users policy mismatch")
	}
}
