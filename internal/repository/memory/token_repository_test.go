// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package memory_test

import (
	"context"
	"testing"
	"time"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestTokenRepositorySaveGetRevoke(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewTokenRepository()
	expires := time.Now().UTC().Add(time.Hour)
	if err := repo.Save(ctx, &domainauth.ClientToken{
		ID:        "abc",
		Subject:   "bot",
		Policies:  []string{"admin"},
		ExpiresAt: expires,
		Renewable: true,
	}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	token, err := repo.Get(ctx, "abc")
	if err != nil || token.Subject != "bot" {
		t.Fatalf("Get() = %v, %+v", err, token)
	}
	if err := repo.Revoke(ctx, "abc", time.Now().UTC()); err != nil {
		t.Fatalf("Revoke() = %v", err)
	}
	token, err = repo.Get(ctx, "abc")
	if err != nil || !token.Revoked {
		t.Fatalf("expected revoked token, got %v %+v", err, token)
	}
}
