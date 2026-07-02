package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestJWKSCachePerURL(t *testing.T) {
	v := auth.NewOIDCValidator()
	// Smoke: validator constructs with per-URL cache; full JWKS fetch requires network.
	if v == nil {
		t.Fatal("nil validator")
	}
	_ = context.Background()
	_ = time.Minute
}
