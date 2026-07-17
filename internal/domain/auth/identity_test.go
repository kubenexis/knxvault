// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"testing"
	"time"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestEntityAliasGroupValidate(t *testing.T) {
	e := &domainauth.Entity{ID: "e1", Name: "alice", Created: time.Now().UTC()}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	a := &domainauth.Alias{ID: "a1", EntityID: "e1", Mount: "oidc", Name: "sub:alice"}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	g := &domainauth.Group{ID: "g1", Name: "admins", MemberIDs: []string{"e1"}, Policies: []string{"admin"}}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&domainauth.Entity{}).Validate(); err == nil {
		t.Fatal("expected entity validation error")
	}
}
