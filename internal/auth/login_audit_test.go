package auth_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestCheckMFAAcceptsNumericACR(t *testing.T) {
	if err := auth.CheckMFA(true, map[string]any{"acr": float64(3)}); err != nil {
		t.Fatalf("CheckMFA() = %v", err)
	}
}

func TestCheckMFAAcceptsStringAMR(t *testing.T) {
	if err := auth.CheckMFA(true, map[string]any{"amr": "mfa"}); err != nil {
		t.Fatalf("CheckMFA() = %v", err)
	}
}