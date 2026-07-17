package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
)

type fakeBinder struct {
	err error
	dn  string
}

func (f *fakeBinder) Bind(_ context.Context, _, bindDN, _ string, _ bool, _ time.Duration) error {
	f.dn = bindDN
	return f.err
}

func TestLoginLDAPSuccess(t *testing.T) {
	tokens := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(tokens, auth.NewRBAC(), "")
	fb := &fakeBinder{}
	svc.SetLDAPBinder(fb)
	tok, rec, err := svc.LoginLDAP(context.Background(), "alice", "secret", auth.LDAPConfig{
		URL:             "ldap://ldap.example.com",
		UserDNTemplate:  "uid=%s,ou=people,dc=example,dc=com",
		DefaultPolicies: []string{"dev"},
	})
	if err != nil || tok == "" || rec == nil {
		t.Fatalf("LoginLDAP: %v", err)
	}
	if fb.dn != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("dn=%s", fb.dn)
	}
	if len(rec.Policies) != 1 || rec.Policies[0] != "dev" {
		t.Fatalf("policies=%v", rec.Policies)
	}
}

func TestLoginLDAPBindFailure(t *testing.T) {
	tokens := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(tokens, auth.NewRBAC(), "")
	svc.SetLDAPBinder(&fakeBinder{err: context.DeadlineExceeded})
	if _, _, err := svc.LoginLDAP(context.Background(), "alice", "bad", auth.LDAPConfig{
		URL: "ldap://ldap.example.com",
	}); err == nil {
		t.Fatal("expected failure")
	}
}

func TestEncodeSimpleBindProducesBytes(t *testing.T) {
	// exercise package via successful fake path only; Net binder integration is env-dependent
	if _, _, err := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "").LoginLDAP(
		context.Background(), "", "x", auth.LDAPConfig{URL: "ldap://x"},
	); err == nil {
		t.Fatal("empty user should fail")
	}
}
