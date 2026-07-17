// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

type failSyncer struct{}

func (failSyncer) SyncRBAC(context.Context) error { return errors.New("sync boom") }

func TestAuthorizeFailClosedOnRBACSyncError(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "allow-all", Effect: domainauth.EffectAllow,
		Resources: []string{"*"}, Actions: []string{"*"},
	})
	svc := auth.NewService(store, rbac, "")
	svc.SetRBACSyncer(failSyncer{})
	svc.SetRBACSyncFailClosed(true)
	principal := auth.Principal{Subject: "u", Policies: []string{"allow-all"}}
	if err := svc.Authorize(context.Background(), principal, "secrets/kv/x", auth.CapRead); err == nil {
		t.Fatal("expected fail-closed on sync error")
	}
	svc.SetRBACSyncFailClosed(false)
	if err := svc.Authorize(context.Background(), principal, "secrets/kv/x", auth.CapRead); err != nil {
		t.Fatalf("fail-open should allow: %v", err)
	}
}
