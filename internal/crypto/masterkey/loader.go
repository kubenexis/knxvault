// Package masterkey loads the application master encryption key.
package masterkey

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const keySize = 32

// Load reads a 32-byte master key from environment or file.
//
// Priority: KNXVAULT_MASTER_KEY_FILE, then KNXVAULT_MASTER_KEY (base64/std).
func Load() ([]byte, error) {
	if path := strings.TrimSpace(os.Getenv("KNXVAULT_MASTER_KEY_FILE")); path != "" {
		return loadFromFile(path)
	}
	if raw := strings.TrimSpace(os.Getenv("KNXVAULT_MASTER_KEY")); raw != "" {
		return decodeKey(raw)
	}
	return nil, fmt.Errorf("master key not configured: set KNXVAULT_MASTER_KEY_FILE or KNXVAULT_MASTER_KEY")
}

func loadFromFile(path string) ([]byte, error) {
	clean, err := validateKeyFilePath(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("read master key file: %w", err)
	}
	return decodeKey(strings.TrimSpace(string(data)))
}

func validateKeyFilePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("read master key file: empty path")
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("read master key file: invalid path")
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("read master key file: path must be absolute")
	}
	info, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("read master key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("read master key file: not a regular file")
	}
	return clean, nil
}

func decodeKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", keySize, len(key))
	}
	return key, nil
}
