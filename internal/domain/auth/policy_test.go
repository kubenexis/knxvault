package auth_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestMatchResource(t *testing.T) {
	if !auth.MatchResource("pki/*", "pki/root") {
		t.Fatal("expected pki/root to match pki/*")
	}
	if auth.MatchResource("secrets/*", "pki/root") {
		t.Fatal("expected pki/root to not match secrets/*")
	}
}
