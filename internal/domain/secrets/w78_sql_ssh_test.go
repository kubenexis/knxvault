// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestW78_SQLStrictFalseRejected(t *testing.T) {
	role := &secrets.DatabaseRole{
		Name:                 "m",
		TTLSeconds:           60,
		UsernamePrefix:       "v-",
		ExecutionMode:        secrets.ExecutionModeManaged,
		AdminCredentialsPath: "db/admin",
		CreationStatements:   []string{`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}';`},
		Config:               map[string]any{"sql_strict": "false"},
	}
	if err := role.Validate(); err == nil {
		t.Fatal("expected sql_strict=false rejection")
	}
}

func TestW78_SSHDefaultNoPortForward(t *testing.T) {
	r := &secrets.SSHRole{Name: "s", TTLSeconds: 60, CAKeyPath: "ssh/ca", DefaultUser: "u"}
	secrets.NormalizeSSHRole(r)
	if _, ok := r.Extensions["permit-port-forwarding"]; ok {
		t.Fatal("port-forwarding must not be default")
	}
	if _, ok := r.Extensions["permit-pty"]; !ok {
		t.Fatal("expected permit-pty")
	}
}
