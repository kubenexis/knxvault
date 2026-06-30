// Package sys tracks one-time bootstrap state.
package sys

import "sync"

var (
	initMu        sync.Mutex
	initialized   bool
	masterKeyFP   string
)

// MarkInitialized records successful bootstrap.
func MarkInitialized(fingerprint string) error {
	initMu.Lock()
	defer initMu.Unlock()
	if initialized {
		return ErrAlreadyInitialized
	}
	initialized = true
	masterKeyFP = fingerprint
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