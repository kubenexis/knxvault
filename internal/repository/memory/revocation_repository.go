// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/repository"
)

// RevocationRepository is an in-memory revocation store.
type RevocationRepository struct {
	mu     sync.RWMutex
	serial map[string]*repository.RevokedCertificate
	byCA   map[uuid.UUID][]*repository.RevokedCertificate
}

// NewRevocationRepository constructs an empty RevocationRepository.
func NewRevocationRepository() *RevocationRepository {
	return &RevocationRepository{
		serial: make(map[string]*repository.RevokedCertificate),
		byCA:   make(map[uuid.UUID][]*repository.RevokedCertificate),
	}
}

// Revoke records a revoked certificate serial.
func (r *RevocationRepository) Revoke(_ context.Context, cert *repository.RevokedCertificate) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.serial[cert.Serial]; exists {
		return nil
	}
	stored := *cert
	r.serial[cert.Serial] = &stored
	r.byCA[cert.CAID] = append(r.byCA[cert.CAID], &stored)
	return nil
}

// IsRevoked reports whether a serial is revoked.
func (r *RevocationRepository) IsRevoked(_ context.Context, serial string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.serial[serial]
	return ok, nil
}

// ListByCA returns revoked certificates for a CA.
func (r *RevocationRepository) ListByCA(_ context.Context, caID uuid.UUID) ([]*repository.RevokedCertificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	src := r.byCA[caID]
	out := make([]*repository.RevokedCertificate, len(src))
	for i, cert := range src {
		stored := *cert
		out[i] = &stored
	}
	return out, nil
}
