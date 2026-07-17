// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package crypto provides envelope encryption and OpenSSL integration (LLD §4).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Envelope encrypts and decrypts payloads with AES-256-GCM.
type Envelope struct {
	key []byte
}

// NewEnvelope creates an Envelope from a 32-byte master key.
func NewEnvelope(masterKey []byte) (*Envelope, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	return &Envelope{key: masterKey}, nil
}

// Encrypt seals plaintext with a random nonce prepended to the ciphertext.
func (e *Envelope) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt opens a payload produced by Encrypt.
func (e *Envelope) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, enc := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, enc, nil)
}
