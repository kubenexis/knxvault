// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package leader_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/infra/leader"
)

func TestMonitorEnforceHealth(t *testing.T) {
	m := leader.NewMonitor()
	if m.EnforceHealth() {
		t.Fatal("expected health not enforced before Activate")
	}
	m.Activate()
	if !m.EnforceHealth() {
		t.Fatal("expected health enforced after Activate")
	}
}

func TestMonitorRunning(t *testing.T) {
	m := leader.NewMonitor()
	if m.Running() {
		t.Fatal("expected not running initially")
	}
	m.SetRunning(true)
	if !m.Running() {
		t.Fatal("expected running")
	}
	m.SetRunning(false)
	if m.Running() {
		t.Fatal("expected not running after stop")
	}
}

func TestNilMonitorRunning(t *testing.T) {
	var m *leader.Monitor
	if !m.Running() {
		t.Fatal("nil monitor should report running for readiness bypass")
	}
	m.SetRunning(false)
}
