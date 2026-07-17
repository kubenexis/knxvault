// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package backup_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/backup"
)

func TestSealArchiveFormat(t *testing.T) {
	cryptoSvc := testCrypto(t)
	snapshot := &backup.Snapshot{
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	data, err := backup.Seal(cryptoSvc, snapshot)
	if err != nil {
		t.Fatalf("Seal() = %v", err)
	}
	var archive backup.Archive
	if err := json.Unmarshal(data, &archive); err != nil {
		t.Fatalf("Unmarshal() = %v", err)
	}
	if archive.Format != "knxvault-backup" {
		t.Fatalf("format = %q, want knxvault-backup", archive.Format)
	}
	if archive.Version != 1 {
		t.Fatalf("version = %d, want 1", archive.Version)
	}
	if len(archive.Ciphertext) == 0 || len(archive.DEKEnc) == 0 {
		t.Fatal("expected encrypted payload fields")
	}
}

func TestOpenRejectsUnsupportedFormat(t *testing.T) {
	cryptoSvc := testCrypto(t)
	raw, _ := json.Marshal(backup.Archive{
		Format:     "other-format",
		Version:    1,
		Ciphertext: []byte("x"),
		DEKEnc:     []byte("y"),
	})
	if _, err := backup.Open(cryptoSvc, raw); err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestOpenRejectsUnsupportedVersion(t *testing.T) {
	cryptoSvc := testCrypto(t)
	raw, _ := json.Marshal(backup.Archive{
		Format:     "knxvault-backup",
		Version:    99,
		Ciphertext: []byte("x"),
		DEKEnc:     []byte("y"),
	})
	if _, err := backup.Open(cryptoSvc, raw); err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestSealRequiresSnapshot(t *testing.T) {
	cryptoSvc := testCrypto(t)
	if _, err := backup.Seal(cryptoSvc, nil); err == nil {
		t.Fatal("expected error for nil snapshot")
	}
}
