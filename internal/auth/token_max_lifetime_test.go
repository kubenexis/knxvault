// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestIssueSetsMaxExpiresAt(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	tok, rec, err := store.Issue(context.Background(), "u", []string{"p"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.MaxExpiresAt.IsZero() {
		t.Fatal("expected MaxExpiresAt set on Issue")
	}
	// Renew far into the future should clamp to max.
	rec2, err := store.Renew(context.Background(), tok, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rec2.ExpiresAt.After(rec.MaxExpiresAt.Add(time.Second)) {
		t.Fatalf("renew past max: exp=%v max=%v", rec2.ExpiresAt, rec.MaxExpiresAt)
	}
	_ = domainauth.EffectAllow
}

func TestCreateTokenSetsMaxExpiresAt(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	svc := auth.NewService(store, rbac, "")
	tok, rec, err := svc.CreateToken(context.Background(), "bot", []string{"admin"}, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if rec.MaxExpiresAt.IsZero() {
		t.Fatal("expected max")
	}
	rec2, err := svc.RenewToken(context.Background(), tok, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rec2.ExpiresAt.After(rec.MaxExpiresAt.Add(time.Second)) {
		t.Fatalf("create token renew past max")
	}
}
