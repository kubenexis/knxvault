package app

import (
	"crypto/subtle"
	"sync"

	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/crypto/autounseal"
	"github.com/kubenexis/knxvault/internal/crypto/memlock"
	"github.com/kubenexis/knxvault/internal/crypto/shamir"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

// SealState tracks operational seal status (distinct from envelope crypto.Seal).
type SealState struct {
	mu              sync.RWMutex
	sealed          bool
	unsealKey       []byte
	scheme          string
	threshold       int
	collectedShares map[int][]byte
	autoUnseal      autounseal.Provider
	breakGlass      bool
}

// NewSealState constructs seal state with the configured unseal key.
func NewSealState(unsealKey []byte) *SealState {
	key := append([]byte(nil), unsealKey...)
	_ = memlock.Lock(key)
	return &SealState{unsealKey: key}
}

// NewSealStateFromConfig builds seal state from seal configuration.
func NewSealStateFromConfig(cfg config.SealConfig, unsealKey []byte, provider autounseal.Provider) *SealState {
	s := &SealState{
		scheme:     cfg.Scheme,
		threshold:  cfg.Threshold,
		autoUnseal: provider,
		breakGlass: cfg.BreakGlassShamir,
	}
	if cfg.ShamirEnabled() {
		s.sealed = true
		s.collectedShares = make(map[int][]byte)
		return s
	}
	if len(unsealKey) > 0 {
		s.unsealKey = append([]byte(nil), unsealKey...)
		_ = memlock.Lock(s.unsealKey)
	}
	return s
}

// TryAutoUnseal attempts KMS/file auto-unseal at startup.
func (s *SealState) TryAutoUnseal() bool {
	if s == nil || s.autoUnseal == nil {
		return false
	}
	key, err := s.autoUnseal.UnsealKey()
	if err != nil {
		return false
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	if s.unseal(key) {
		metrics.IncAutoUnsealSuccess()
		return true
	}
	return false
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

// UnsealProgress returns collected share count and threshold (Shamir mode).
func (s *SealState) UnsealProgress() (progress, threshold int) {
	if s == nil {
		return 0, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.shamirMode() {
		return 0, 0
	}
	return len(s.collectedShares), s.threshold
}

// Seal blocks mutating operations until unseal.
func (s *SealState) Seal() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed = true
	if s.shamirModeLocked() {
		s.collectedShares = make(map[int][]byte)
	}
}

// Unseal restores service when the key matches (single-key mode).
func (s *SealState) Unseal(key []byte) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unseal(key)
}

// SubmitShare accepts a Shamir share and unseals when threshold is met.
func (s *SealState) SubmitShare(shareID int, share []byte) (ok bool, progress, threshold int) {
	if s == nil || shareID < 1 || len(share) == 0 {
		return false, 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.shamirModeLocked() && !(s.breakGlass && len(s.unsealKey) > 0) {
		return s.unseal(share), 0, 0
	}
	if s.collectedShares == nil {
		s.collectedShares = make(map[int][]byte)
	}
	s.collectedShares[shareID] = append([]byte(nil), share...)
	progress = len(s.collectedShares)
	threshold = s.threshold
	if progress < threshold {
		metrics.IncShamirUnsealShare()
		return false, progress, threshold
	}
	parts := make([][]byte, 0, progress)
	for _, part := range s.collectedShares {
		parts = append(parts, part)
	}
	secret, err := shamir.Combine(parts)
	if err != nil {
		return false, progress, threshold
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	if !s.unseal(secret) {
		return false, progress, threshold
	}
	metrics.IncShamirUnsealSuccess()
	s.collectedShares = make(map[int][]byte)
	return true, threshold, threshold
}

// Close unlocks sensitive memory.
func (s *SealState) Close() {
	if s == nil || len(s.unsealKey) == 0 {
		return
	}
	_ = memlock.Unlock(s.unsealKey)
	s.unsealKey = nil
}

func (s *SealState) shamirMode() bool {
	return s.shamirModeLocked()
}

func (s *SealState) shamirModeLocked() bool {
	return s != nil && s.scheme == config.UnsealSchemeShamir && s.threshold >= 2
}

func (s *SealState) unseal(key []byte) bool {
	if len(s.unsealKey) == 0 {
		if len(key) == 0 {
			return false
		}
		s.unsealKey = append([]byte(nil), key...)
		_ = memlock.Lock(s.unsealKey)
		s.sealed = false
		return true
	}
	if len(key) != len(s.unsealKey) || subtle.ConstantTimeCompare(key, s.unsealKey) != 1 {
		return false
	}
	s.sealed = false
	return true
}
