// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package leader

import "sync"

// Monitor tracks whether the leader election goroutine is alive.
type Monitor struct {
	mu      sync.RWMutex
	active  bool
	running bool
}

// NewMonitor constructs an election health monitor.
func NewMonitor() *Monitor {
	return &Monitor{}
}

// Activate marks that background jobs started and /ready should enforce election health.
func (m *Monitor) Activate() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.active = true
	m.mu.Unlock()
}

// EnforceHealth reports whether election loop health gates readiness.
func (m *Monitor) EnforceHealth() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
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
