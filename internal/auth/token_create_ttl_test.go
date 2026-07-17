// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestCreateTokenClampsMaxTTL(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(store, auth.NewRBAC(), "")
	token, rec, err := svc.CreateToken(context.Background(), "u", []string{"admin"}, 365*24*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	if rec.ExpiresAt.After(time.Now().Add(auth.MaxClientTokenTTL + time.Minute)) {
		t.Fatalf("ttl not clamped: expires %v", rec.ExpiresAt)
	}
}
