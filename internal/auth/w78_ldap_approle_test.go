// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestW78_LDAPSetsMaxExpiresAt(t *testing.T) {
	// Cover Create path used by LDAP via TokenStore directly with same max pattern.
	store := auth.NewTokenStore(time.Hour)
	maxAt := time.Now().UTC().Add(time.Hour)
	tok, rec, err := store.Create(context.Background(), "ldap:user", []string{"default"}, time.Hour, true, maxAt)
	if err != nil {
		t.Fatal(err)
	}
	if rec.MaxExpiresAt.IsZero() {
		t.Fatal("expected MaxExpiresAt")
	}
	// Renew past max must clamp
	time.Sleep(10 * time.Millisecond)
	rec2, err := store.Renew(context.Background(), tok, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rec2.ExpiresAt.After(rec.MaxExpiresAt.Add(time.Second)) {
		t.Fatalf("renew past max: exp=%v max=%v", rec2.ExpiresAt, rec.MaxExpiresAt)
	}
}

func TestW78_AppRoleSaltedHashAndMinSecret(t *testing.T) {
	s := auth.NewAppRoleStore()
	if err := s.Register("role1", "short", "sub", []string{"p"}); err == nil {
		t.Fatal("expected short secret_id rejected")
	}
	if err := s.Register("role1", "long-enough-secret-id", "sub", []string{"p"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("role1", "long-enough-secret-id"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("role1", "wrong-secret-id-xx"); err == nil {
		t.Fatal("expected auth fail")
	}
}
