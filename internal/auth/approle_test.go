// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestAppRoleRegisterAndLogin(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(store, auth.NewRBAC(), "")
	ctx := context.Background()

	const secret = "secret-cm-long-ok"
	if err := svc.RegisterAppRole("role-cm", secret, "cert-manager", []string{"pki-admin"}); err != nil {
		t.Fatalf("RegisterAppRole() = %v", err)
	}

	token, record, err := svc.LoginAppRole(ctx, "role-cm", secret)
	if err != nil {
		t.Fatalf("LoginAppRole() = %v", err)
	}
	if token == "" {
		t.Fatal("expected token")
	}
	if record.Subject != "cert-manager" {
		t.Fatalf("subject = %q", record.Subject)
	}
	if len(record.Policies) != 1 || record.Policies[0] != "pki-admin" {
		t.Fatalf("policies = %v", record.Policies)
	}

	// Wrong secret
	if _, _, err := svc.LoginAppRole(ctx, "role-cm", "wrong"); err == nil {
		t.Fatal("expected error for wrong secret_id")
	}
	// Unknown role
	if _, _, err := svc.LoginAppRole(ctx, "nope", secret); err == nil {
		t.Fatal("expected error for unknown role_id")
	}
}

func TestAppRoleRegisterValidation(t *testing.T) {
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	if err := svc.RegisterAppRole("", "s", "sub", []string{"admin"}); err == nil {
		t.Fatal("expected validation error")
	}
	if err := svc.RegisterAppRole("r", "s", "sub", nil); err == nil {
		t.Fatal("expected policies required")
	}
}
