// Package autounseal provides pluggable auto-unseal providers (KMS stubs until LT-14).
package autounseal

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Provider attempts to recover the operational unseal key at startup.
type Provider interface {
	Name() string
	UnsealKey() ([]byte, error)
}

// FileProvider reads a base64 unseal key from a local file (dev/stub for LT-14 KMS).
type FileProvider struct {
	Path string
}

// Name returns the provider identifier.
func (p *FileProvider) Name() string { return "file" }

// UnsealKey loads the key from the configured path.
func (p *FileProvider) UnsealKey() ([]byte, error) {
	if strings.TrimSpace(p.Path) == "" {
		return nil, fmt.Errorf("auto-unseal file path not configured")
	}
	data, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, fmt.Errorf("read auto-unseal key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode auto-unseal key: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("auto-unseal key is empty")
	}
	return raw, nil
}

// NewProvider constructs a provider from config.
func NewProvider(provider, keyFile string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "none":
		return nil, nil
	case "file":
		return &FileProvider{Path: keyFile}, nil
	default:
		return nil, fmt.Errorf("unsupported auto-unseal provider %q", provider)
	}
}
