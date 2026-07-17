// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package filestore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CertRecord is metadata for a delivered ACME certificate (no private key).
type CertRecord struct {
	Profile      string    `json:"profile,omitempty"`
	CommonName   string    `json:"common_name"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	DirectoryURL string    `json:"directory_url,omitempty"`
	CertPath     string    `json:"cert_path"`
	KeyPath      string    `json:"key_path"`
	Serial       string    `json:"serial,omitempty"`
	NotBefore    time.Time `json:"not_before,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// CertStateFile stores CertRecord as JSON next to delivered material.
type CertStateFile struct {
	Path string
}

// Load reads the state file; (nil, nil) if missing.
func (c CertStateFile) Load() (*CertRecord, error) {
	if c.Path == "" {
		return nil, fmt.Errorf("cert state path is required")
	}
	b, err := os.ReadFile(c.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rec CertRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("cert state corrupt: %w", err)
	}
	return &rec, nil
}

// Save writes the record atomically with 0600 mode.
func (c CertStateFile) Save(rec *CertRecord) error {
	if c.Path == "" {
		return fmt.Errorf("cert state path is required")
	}
	if rec == nil {
		return fmt.Errorf("cert record is nil")
	}
	rec.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return err
	}
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}

// NeedsRenew reports whether renewal should run given renewBefore duration.
func (r *CertRecord) NeedsRenew(now time.Time, renewBefore time.Duration) bool {
	if r == nil || r.NotAfter.IsZero() {
		return true
	}
	if renewBefore <= 0 {
		renewBefore = 720 * time.Hour
	}
	return !now.Add(renewBefore).Before(r.NotAfter)
}
