package openssl_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto/openssl"
)

func TestBreakerOpensAfterFailures(t *testing.T) {
	b := openssl.NewBreaker(2, time.Minute)
	b.RecordFailure()
	if err := b.Allow(); err != nil {
		t.Fatalf("expected closed breaker, got %v", err)
	}
	b.RecordFailure()
	if err := b.Allow(); err != openssl.ErrCircuitOpen {
		t.Fatalf("expected open breaker, got %v", err)
	}
	b.RecordSuccess()
	if err := b.Allow(); err != nil {
		t.Fatalf("expected closed breaker after success, got %v", err)
	}
}
