package leader

import "sync"

// Monitor tracks whether the leader election goroutine is alive.
type Monitor struct {
	mu      sync.RWMutex
	running bool
}

// NewMonitor constructs an election health monitor.
func NewMonitor() *Monitor {
	return &Monitor{}
}

// SetRunning records whether the election loop is active.
func (m *Monitor) SetRunning(running bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.running = running
	m.mu.Unlock()
}

// Running reports whether the election loop is active.
func (m *Monitor) Running() bool {
	if m == nil {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}
