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

func TestLoginLDAPRequiresServerConfig(t *testing.T) {
	tokens := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(tokens, auth.NewRBAC(), "")
	// No LDAPDefaults — must fail closed even with client-looking config args.
	if _, _, err := svc.LoginLDAP(context.Background(), "alice", "secret", auth.LDAPConfig{
		URL: "ldap://evil.example.com",
	}); err == nil {
		t.Fatal("expected ldap not configured")
	}
}

func TestLoginLDAPSuccessWithServerDefaults(t *testing.T) {
	tokens := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(tokens, auth.NewRBAC(), "")
	svc.SetLDAPDefaults(&auth.LDAPConfig{
		URL:             "ldap://ldap.example.com",
		UserDNTemplate:  "uid=%s,ou=people,dc=example,dc=com",
		DefaultPolicies: []string{"dev"},
	})
	fb := &fakeBinder{}
	svc.SetLDAPBinder(fb)
	// Client-supplied cfg must be ignored.
	tok, rec, err := svc.LoginLDAP(context.Background(), "alice", "secret", auth.LDAPConfig{
		URL:             "ldap://attacker",
		DefaultPolicies: []string{"admin"},
	})
	if err != nil || tok == "" || rec == nil {
		t.Fatalf("LoginLDAP: %v", err)
	}
	if fb.dn != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("dn=%s", fb.dn)
	}
	if len(rec.Policies) != 1 || rec.Policies[0] != "dev" {
		t.Fatalf("policies=%v want server defaults", rec.Policies)
	}
}

func TestLoginLDAPRejectsInjectionUsername(t *testing.T) {
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetLDAPDefaults(&auth.LDAPConfig{URL: "ldap://ldap.example.com", UserDNTemplate: "uid=%s,dc=x"})
	svc.SetLDAPBinder(&fakeBinder{})
	if _, _, err := svc.LoginLDAP(context.Background(), "alice)(|(uid=*", "x", auth.LDAPConfig{}); err == nil {
		t.Fatal("expected invalid username")
	}
}

func TestLoginLDAPBindFailure(t *testing.T) {
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetLDAPDefaults(&auth.LDAPConfig{URL: "ldap://ldap.example.com"})
	svc.SetLDAPBinder(&fakeBinder{err: context.DeadlineExceeded})
	if _, _, err := svc.LoginLDAP(context.Background(), "alice", "bad", auth.LDAPConfig{}); err == nil {
		t.Fatal("expected failure")
	}
}

func TestValidateLDAPUsername(t *testing.T) {
	if err := auth.ValidateLDAPUsername("alice.smith+1@corp"); err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateLDAPUsername(""); err == nil {
		t.Fatal("empty")
	}
	if err := auth.ValidateLDAPUsername("a*b"); err == nil {
		t.Fatal("meta")
	}
}

func TestLDAPConfigured(t *testing.T) {
	s := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	if s.LDAPConfigured() {
		t.Fatal("expected not configured")
	}
	s.SetLDAPDefaults(&auth.LDAPConfig{URL: "ldaps://ldap.example.com"})
	if !s.LDAPConfigured() {
		t.Fatal("expected configured")
	}
}
