// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package vaultstore

import (
	"fmt"
)

// Config will hold knxvault API address and token for optional ACME state.
type Config struct {
	Addr  string
	Token string
	// PathPrefix is the KV or internal path prefix (future).
	PathPrefix string
}

// Store is not implemented in M-ACME-1 (see ADR-0010).
type Store struct {
	cfg Config
}

// New returns a Store that reports not implemented until W60-16.
func New(cfg Config) *Store {
	return &Store{cfg: cfg}
}

// ErrNotImplemented is returned by all vaultstore operations until W60-16.
var ErrNotImplemented = fmt.Errorf("acme vaultstore: not implemented (M-ACME-2 / W60-16; use file store)")

// LoadAccountKey stub.
func (s *Store) LoadAccountKey() error {
	return ErrNotImplemented
}

// SaveAccountKey stub.
func (s *Store) SaveAccountKey() error {
	return ErrNotImplemented
}
