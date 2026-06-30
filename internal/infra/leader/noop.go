package leader

import "context"

// NoopElector always considers itself the leader (single-instance mode).
type NoopElector struct{}

// NewNoopElector returns an elector suitable for non-HA deployments.
func NewNoopElector() *NoopElector {
	return &NoopElector{}
}

// Run invokes onLeadership immediately and blocks until ctx is cancelled.
func (e *NoopElector) Run(ctx context.Context, onLeadership func(ctx context.Context)) error {
	onLeadership(ctx)
	<-ctx.Done()
	return ctx.Err()
}

// IsLeader always returns true.
func (e *NoopElector) IsLeader() bool {
	return true
}
