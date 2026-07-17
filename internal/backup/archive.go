// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"encoding/json"
	"fmt"
	"time"

	kvncrypto "github.com/kubenexis/knxvault/internal/crypto"
)

// Archive is an encrypted on-disk backup envelope.
type Archive struct {
	Format     string    `json:"format"`
	Version    int       `json:"version"`
	CreatedAt  time.Time `json:"created_at"`
	Ciphertext []byte    `json:"ciphertext"`
	DEKEnc     []byte    `json:"dek_enc"`
}

// Seal encrypts a snapshot with the master key crypto service.
func Seal(cryptoSvc *kvncrypto.Service, snapshot *Snapshot) ([]byte, error) {
	if cryptoSvc == nil {
		return nil, fmt.Errorf("crypto service not configured")
	}
	if snapshot == nil {
		return nil, fmt.Errorf("snapshot is required")
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	ciphertext, dekEnc, err := cryptoSvc.Seal(raw)
	if err != nil {
		return nil, fmt.Errorf("seal snapshot: %w", err)
	}
	archive := Archive{
		Format:     "knxvault-backup",
		Version:    formatVersion,
		CreatedAt:  time.Now().UTC(),
		Ciphertext: ciphertext,
		DEKEnc:     dekEnc,
	}
	return json.Marshal(archive)
}

// Open decrypts an archive and returns the snapshot.
func Open(cryptoSvc *kvncrypto.Service, data []byte) (*Snapshot, error) {
	if cryptoSvc == nil {
		return nil, fmt.Errorf("crypto service not configured")
	}
	var archive Archive
	if err := json.Unmarshal(data, &archive); err != nil {
		return nil, fmt.Errorf("parse archive: %w", err)
	}
	if archive.Format != "knxvault-backup" {
		return nil, fmt.Errorf("unsupported archive format %q", archive.Format)
	}
	if archive.Version != formatVersion {
		return nil, fmt.Errorf("unsupported archive version %d", archive.Version)
	}
	raw, err := cryptoSvc.Open(archive.Ciphertext, archive.DEKEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt archive: %w", err)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}
	if err := ValidateSnapshot(&snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}
