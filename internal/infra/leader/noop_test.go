package leader_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/infra/leader"
)

func TestNoopElector(t *testing.T) {
	e := leader.NewNoopElector()
	if !e.IsLeader() {
		t.Fatal("expected noop elector to be leader")
	}

	ctx, cancel := context.WithCancel(context.Background())
	led := make(chan struct{}, 1)
	go func() {
		_ = e.Run(ctx, func(context.Context) {
			led <- struct{}{}
			<-ctx.Done()
		})
	}()

	select {
	case <-led:
	case <-time.After(time.Second):
		t.Fatal("expected leadership callback")
	}
	cancel()
}
