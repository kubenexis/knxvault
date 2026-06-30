// Package leader provides HA leader election abstractions (LLD §6.2).
package leader

import "context"

// Elector coordinates exclusive background work across replicas.
type Elector interface {
	// Run blocks until ctx is cancelled, invoking onLeadership when elected.
	Run(ctx context.Context, onLeadership func(ctx context.Context)) error
	// IsLeader reports whether this instance currently holds leadership.
	IsLeader() bool
}
