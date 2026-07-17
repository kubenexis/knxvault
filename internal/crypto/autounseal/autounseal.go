// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package autounseal decrypts the operational unseal key using an external KEK (W63 / P3).
// Provider "aes-kek" uses AES-256-GCM: ciphertext is nonce||ciphertext produced with the KEK.
// Cloud KMS material is injected as KEK via CSI/Secrets Manager; knxvault does not embed cloud SDKs.
package autounseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// Config for auto-unseal decryption.
type Config struct {
	Provider   string
	Ciphertext string // base64
	KEK        string // base64 32-byte key
}

// DecryptUnsealKey returns the raw unseal key bytes.
func DecryptUnsealKey(cfg Config) ([]byte, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	switch provider {
	case "", "none":
		return nil, fmt.Errorf("auto-unseal provider not set")
	case "aes-kek":
		return decryptAESKEK(cfg.Ciphertext, cfg.KEK)
	default:
		return nil, fmt.Errorf("unknown auto-unseal provider %q (supported: aes-kek)", cfg.Provider)
	}
}

// SealUnsealKey encrypts unseal key with KEK for operators generating ciphertext offline.
func SealUnsealKey(unsealKey, kek []byte) (string, error) {
	if len(kek) != 32 {
		return "", fmt.Errorf("kek must be 32 bytes")
	}
	if len(unsealKey) == 0 {
		return "", fmt.Errorf("unseal key empty")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, unsealKey, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

func decryptAESKEK(ciphertextB64, kekB64 string) ([]byte, error) {
	kek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(kekB64))
	if err != nil {
		return nil, fmt.Errorf("decode kek: %w", err)
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("kek must decode to 32 bytes, got %d", len(kek))
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ciphertextB64))
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt unseal key: %w", err)
	}
	return pt, nil
}
