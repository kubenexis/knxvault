package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestTokenIssueAuthenticate(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	token, record, err := store.Issue("alice", []string{"secrets-reader"})
	if err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	if record.Subject != "alice" {
		t.Fatalf("subject = %q", record.Subject)
	}

	got, err := store.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate() = %v", err)
	}
	if got.Subject != "alice" {
		t.Fatalf("authenticated subject = %q", got.Subject)
	}
}

func TestLoginKubernetes(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(store, auth.NewRBAC(), "test-secret")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "system:serviceaccount:default:demo",
	})
	signed, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("SignedString() = %v", err)
	}

	clientToken, record, err := svc.LoginKubernetes(context.Background(), "secrets-reader", signed)
	if err != nil {
		t.Fatalf("LoginKubernetes() = %v", err)
	}
	if clientToken == "" || record == nil {
		t.Fatal("expected client token")
	}
}
