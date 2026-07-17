// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

func TestMatchServiceAccountBinding(t *testing.T) {
	role := &domainauth.Role{
		Name:                          "app-sa",
		Policies:                      []string{"app"},
		BoundServiceAccountNames:      []string{"my-app"},
		BoundServiceAccountNamespaces: []string{"prod"},
	}
	id := auth.ServiceAccountIdentity{Namespace: "prod", Name: "my-app"}
	if err := auth.MatchServiceAccountBinding(role, id); err != nil {
		t.Fatalf("expected match: %v", err)
	}
	id.Name = "other"
	if err := auth.MatchServiceAccountBinding(role, id); err == nil {
		t.Fatal("expected forbidden for wrong SA")
	}
}

func TestParseServiceAccountUsername(t *testing.T) {
	id, ok := auth.ParseServiceAccountUsername("system:serviceaccount:prod:my-app")
	if !ok || id.Namespace != "prod" || id.Name != "my-app" {
		t.Fatalf("parse failed: %+v %v", id, ok)
	}
}

func TestMatchServiceAccountBindingRequiresBindings(t *testing.T) {
	role := &domainauth.Role{Name: "open", Policies: []string{"admin"}}
	err := auth.MatchServiceAccountBinding(role, auth.ServiceAccountIdentity{Namespace: "default", Name: "app"})
	if err == nil {
		t.Fatal("expected bindings required")
	}
	var kv *common.KNXVaultError
	if !errorsAs(err, &kv) || kv.Code != common.ErrCodeForbidden {
		t.Fatalf("got err %v", err)
	}
}

func TestMatchServiceAccountBindingRequiresIdentity(t *testing.T) {
	role := &domainauth.Role{
		Name:                     "bound",
		Policies:                 []string{"app"},
		BoundServiceAccountNames: []string{"app"},
	}
	err := auth.MatchServiceAccountBinding(role, auth.ServiceAccountIdentity{})
	if err == nil {
		t.Fatal("expected error")
	}
	var kv *common.KNXVaultError
	if !errorsAs(err, &kv) || kv.Code != common.ErrCodeForbidden {
		t.Fatalf("got err %v", err)
	}
}

func errorsAs(err error, target **common.KNXVaultError) bool {
	if err == nil {
		return false
	}
	if kv, ok := err.(*common.KNXVaultError); ok {
		*target = kv
		return true
	}
	return false
}
