// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package sys tracks one-time bootstrap state.
package sys

import (
	"os"
	"path/filepath"
	"sync"
)

var (
	initMu      sync.Mutex
	initialized bool
	masterKeyFP string
	statePath   string
)

// SetStatePath enables durable init marker (W50-05). Call before MarkInitialized.
func SetStatePath(path string) {
	initMu.Lock()
	defer initMu.Unlock()
	statePath = path
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		initialized = true
		masterKeyFP = string(raw)
	}
}

// MarkInitialized records successful bootstrap.
func MarkInitialized(fingerprint string) error {
	initMu.Lock()
	defer initMu.Unlock()
	if initialized {
		return ErrAlreadyInitialized
	}
	initialized = true
	masterKeyFP = fingerprint
	if statePath != "" {
		_ = os.MkdirAll(filepath.Dir(statePath), 0o700)
		_ = os.WriteFile(statePath, []byte(fingerprint), 0o600)
	}
	return nil
}

// Initialized reports whether bootstrap completed.
func Initialized() bool {
	initMu.Lock()
	defer initMu.Unlock()
	return initialized
}

// MasterKeyFingerprint returns the fingerprint set at init.
func MasterKeyFingerprint() string {
	initMu.Lock()
	defer initMu.Unlock()
	return masterKeyFP
}

// ResetForTest clears init state (unit tests only).
func ResetForTest() {
	initMu.Lock()
	defer initMu.Unlock()
	initialized = false
	masterKeyFP = ""
	statePath = ""
}
