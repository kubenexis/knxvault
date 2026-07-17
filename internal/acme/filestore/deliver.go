package filestore

import (
	"fmt"
	"os"
	"path/filepath"
)

// WritePEMFiles writes certificate and key PEMs atomically (cert 0644, key 0600).
func WritePEMFiles(certPath, keyPath, certPEM, keyPEM string) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("cert and key paths are required")
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(certPath, []byte(certPEM), 0o644); err != nil {
		return err
	}
	return writeAtomic(keyPath, []byte(keyPEM), 0o600)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
