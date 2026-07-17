// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
)

// AccountKeyFile loads/stores ACME account keys as PEM files (mode 0600).
type AccountKeyFile struct {
	Path string
}

// Load returns the account key if the file exists; (nil, nil) if missing.
func (a AccountKeyFile) Load() (crypto.Signer, error) {
	if a.Path == "" {
		return nil, fmt.Errorf("account key path is required")
	}
	b, err := os.ReadFile(a.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return ParseAccountKeyPEM(b)
}

// Store writes the account key PEM with 0600 permissions (atomic rename).
func (a AccountKeyFile) Store(key crypto.Signer) error {
	if a.Path == "" {
		return fmt.Errorf("account key path is required")
	}
	if key == nil {
		return fmt.Errorf("account key is nil")
	}
	pemBytes, err := MarshalAccountKeyPEM(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.Path), 0o700); err != nil {
		return err
	}
	tmp := a.Path + ".tmp"
	if err := os.WriteFile(tmp, pemBytes, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.Path)
}

// LoadOrCreate returns an existing key or generates and stores a new one.
func (a AccountKeyFile) LoadOrCreate() (crypto.Signer, error) {
	key, err := a.Load()
	if err != nil {
		return nil, err
	}
	if key != nil {
		return key, nil
	}
	key, err = GenerateAccountKey()
	if err != nil {
		return nil, err
	}
	if err := a.Store(key); err != nil {
		return nil, err
	}
	return key, nil
}
