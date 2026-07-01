package app

import (
	"crypto/subtle"
	"sync"
)

// SealState tracks operational seal status (distinct from envelope crypto.Seal).
type SealState struct {
	mu        sync.RWMutex
	sealed    bool
	unsealKey []byte
}

// NewSealState constructs seal state with the configured unseal key.
func NewSealState(unsealKey []byte) *SealState {
	key := append([]byte(nil), unsealKey...)
	return &SealState{unsealKey: key}
}

// Sealed reports whether the vault is operationally sealed.
func (s *SealState) Sealed() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed
}

// Seal blocks mutating operations until unseal.
func (s *SealState) Seal() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed = true
}

// Unseal restores service when the key matches.
func (s *SealState) Unseal(key []byte) bool {
	if s == nil || len(s.unsealKey) == 0 {
		return false
	}
	if len(key) != len(s.unsealKey) || subtle.ConstantTimeCompare(key, s.unsealKey) != 1 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed = false
	return true
}
