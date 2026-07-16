package app

import (
	"crypto/subtle"
	"os"
	"path/filepath"
	"sync"
)

// SealState tracks operational seal status (distinct from envelope crypto.Seal).
type SealState struct {
	mu        sync.RWMutex
	sealed    bool
	unsealKey []byte
	stateFile string // optional durable flag path
}

// NewSealState constructs seal state with the configured unseal key.
// When an unseal key is configured, the vault starts sealed (W50-03) until
// a matching unseal is presented.
func NewSealState(unsealKey []byte) *SealState {
	key := append([]byte(nil), unsealKey...)
	s := &SealState{unsealKey: key}
	if len(key) > 0 {
		s.sealed = true
	}
	return s
}

// SetStateFile enables durable seal flag persistence (path to a small marker file).
func (s *SealState) SetStateFile(path string) {
	if s == nil || path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateFile = path
	// If marker says sealed, or unseal key present with no unsealed marker, stay sealed.
	if b, err := os.ReadFile(path); err == nil {
		if string(b) == "sealed" {
			s.sealed = true
		} else if string(b) == "unsealed" && len(s.unsealKey) > 0 {
			// Only honor unsealed if file present; default with key is sealed.
			s.sealed = false
		}
	}
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

// Seal blocks the data plane until unseal.
func (s *SealState) Seal() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed = true
	s.persistLocked()
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
	s.persistLocked()
	return true
}

func (s *SealState) persistLocked() {
	if s.stateFile == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.stateFile), 0o700)
	val := "unsealed"
	if s.sealed {
		val = "sealed"
	}
	_ = os.WriteFile(s.stateFile, []byte(val), 0o600)
}
