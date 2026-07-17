// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/subtle"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto/shamir"
)

func combineShares(list [][]byte) ([]byte, error) {
	return shamir.Combine(list)
}

// SealState tracks operational seal status (distinct from envelope crypto.Seal).
type SealState struct {
	mu           sync.RWMutex
	sealed       bool
	unsealKey    []byte
	stateFile    string // optional durable flag path
	failCount    int
	lastFail     time.Time
	maxFailDelay time.Duration
	// Multi-share (Shamir) unseal: threshold t of n shares.
	threshold int
	pending   map[byte][]byte // x -> full share bytes
}

// NewSealState constructs seal state with the configured unseal key.
// When an unseal key is configured, the vault starts sealed (W50-03) until
// a matching unseal is presented.
func NewSealState(unsealKey []byte) *SealState {
	key := append([]byte(nil), unsealKey...)
	s := &SealState{unsealKey: key, threshold: 1, pending: make(map[byte][]byte)}
	if len(key) > 0 {
		s.sealed = true
	}
	return s
}

// SetUnsealThreshold configures Shamir threshold (t). Values <=1 keep single-key unseal.
func (s *SealState) SetUnsealThreshold(t int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t < 1 {
		t = 1
	}
	s.threshold = t
	s.pending = make(map[byte][]byte)
}

// SetStateFile enables durable seal flag persistence (path to a small marker file).
// Security (W52-01): the on-disk marker must NEVER unseal the vault by itself.
// Only a successful cryptographic Unseal may clear sealed state. The file may
// record "sealed" across restarts (sticky seal) or be written after live unseal
// for operators; reading "unsealed" from disk is ignored when an unseal key exists.
func (s *SealState) SetStateFile(path string) {
	if s == nil || path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateFile = path
	if b, err := os.ReadFile(path); err == nil {
		if string(b) == "sealed" {
			// Sticky seal across restart.
			s.sealed = true
		}
		// Intentionally ignore "unsealed" on disk when unsealKey is configured:
		// process still starts sealed until Unseal(key) succeeds.
	}
	// If unseal key is configured, ensure we remain sealed after load.
	if len(s.unsealKey) > 0 {
		s.sealed = true
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

// Unseal restores service when the full unseal key matches.
// Failed attempts apply progressive backoff (W50-28) before accepting another try.
func (s *SealState) Unseal(key []byte) bool {
	if s == nil || len(s.unsealKey) == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if wait := s.unsealBackoffLocked(time.Now()); wait > 0 {
		return false
	}
	if len(key) != len(s.unsealKey) || subtle.ConstantTimeCompare(key, s.unsealKey) != 1 {
		s.failCount++
		s.lastFail = time.Now()
		return false
	}
	return s.markUnsealedLocked()
}

// UnsealProgress reports Shamir share progress (have, need).
func (s *SealState) UnsealProgress() (have, need int) {
	if s == nil {
		return 0, 1
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	need = s.threshold
	if need < 1 {
		need = 1
	}
	return len(s.pending), need
}

// SubmitShare adds a Shamir share. When threshold shares are collected and
// combine to the unseal key, the vault unseals.
func (s *SealState) SubmitShare(share []byte) (unsealed bool, have, need int, errMsg string) {
	if s == nil || len(s.unsealKey) == 0 {
		return false, 0, 1, "unseal not configured"
	}
	if len(share) < 2 {
		return false, 0, 1, "invalid share"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	need = s.threshold
	if need < 1 {
		need = 1
	}
	if wait := s.unsealBackoffLocked(time.Now()); wait > 0 {
		return false, len(s.pending), need, "unseal rate limited"
	}
	x := share[0]
	cp := append([]byte(nil), share...)
	s.pending[x] = cp
	have = len(s.pending)
	if have < need {
		return false, have, need, ""
	}
	// Collect shares and try combine.
	list := make([][]byte, 0, have)
	for _, sh := range s.pending {
		list = append(list, sh)
	}
	// Import shamir at package level - need to add import
	combined, err := combineShares(list)
	if err != nil {
		s.failCount++
		s.lastFail = time.Now()
		return false, have, need, "share combine failed"
	}
	if len(combined) != len(s.unsealKey) || subtle.ConstantTimeCompare(combined, s.unsealKey) != 1 {
		s.failCount++
		s.lastFail = time.Now()
		s.pending = make(map[byte][]byte)
		return false, 0, need, "invalid shares"
	}
	s.pending = make(map[byte][]byte)
	return s.markUnsealedLocked(), need, need, ""
}

func (s *SealState) markUnsealedLocked() bool {
	s.failCount = 0
	s.lastFail = time.Time{}
	s.sealed = false
	s.pending = make(map[byte][]byte)
	s.persistLocked()
	return true
}

// UnsealRetryAfter returns remaining backoff after a failed unseal (0 if ready).
func (s *SealState) UnsealRetryAfter() time.Duration {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unsealBackoffLocked(time.Now())
}

func (s *SealState) unsealBackoffLocked(now time.Time) time.Duration {
	if s.failCount <= 0 {
		return 0
	}
	// Progressive: 1s, 2s, 4s, ... capped at 30s (or maxFailDelay).
	capDelay := s.maxFailDelay
	if capDelay <= 0 {
		capDelay = 30 * time.Second
	}
	shift := s.failCount - 1
	if shift > 5 {
		shift = 5
	}
	delay := time.Duration(1<<uint(shift)) * time.Second
	if delay > capDelay {
		delay = capDelay
	}
	elapsed := now.Sub(s.lastFail)
	if elapsed >= delay {
		return 0
	}
	return delay - elapsed
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
