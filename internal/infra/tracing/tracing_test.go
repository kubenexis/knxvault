package tracing_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/infra/tracing"
)

func TestInitDisabled(t *testing.T) {
	shutdown, err := tracing.Init(context.Background(), config.Config{})
	if err != nil {
		t.Fatalf("Init() = %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown() = %v", err)
	}
}
