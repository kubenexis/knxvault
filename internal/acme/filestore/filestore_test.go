// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package filestore_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/acme/filestore"
)

func TestCertStateNeedsRenew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store := filestore.CertStateFile{Path: path}
	rec := &filestore.CertRecord{
		CommonName: "a.example",
		CertPath:   filepath.Join(dir, "c.pem"),
		KeyPath:    filepath.Join(dir, "k.pem"),
		NotAfter:   time.Now().UTC().Add(24 * time.Hour),
	}
	if err := store.Save(rec); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded == nil {
		t.Fatalf("Load: %v %v", loaded, err)
	}
	if !loaded.NeedsRenew(time.Now().UTC(), 720*time.Hour) {
		t.Fatal("expected needs renew within 30d of 24h remaining")
	}
	loaded.NotAfter = time.Now().UTC().Add(900 * time.Hour)
	if loaded.NeedsRenew(time.Now().UTC(), 720*time.Hour) {
		t.Fatal("should not need renew")
	}
	// corrupt file
	_ = os.WriteFile(path, []byte("{"), 0o600)
	if _, err := store.Load(); err == nil {
		t.Fatal("expected corrupt error")
	}
}

func TestWritePEMFiles(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "fullchain.pem")
	key := filepath.Join(dir, "key.pem")
	if err := filestore.WritePEMFiles(cert, key, "CERT\n", "KEY\n"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cert)
	if string(b) != "CERT\n" {
		t.Fatalf("cert %q", b)
	}
	info, _ := os.Stat(key)
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("key perms %v", info.Mode())
	}
}

func TestCertStateMissing(t *testing.T) {
	s := filestore.CertStateFile{Path: filepath.Join(t.TempDir(), "no.json")}
	r, err := s.Load()
	if err != nil || r != nil {
		t.Fatalf("%v %v", r, err)
	}
}

func TestWritePEMFilesErrors(t *testing.T) {
	if err := filestore.WritePEMFiles("", "/k", "c", "k"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCertStateSaveNil(t *testing.T) {
	s := filestore.CertStateFile{Path: t.TempDir() + "/s.json"}
	if err := s.Save(nil); err == nil {
		t.Fatal("expected error")
	}
}
