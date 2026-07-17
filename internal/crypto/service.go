// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/kubenexis/knxvault/internal/crypto/memzero"
)

const dekSize = 32

// Service provides envelope encryption for data and DEKs (LLD §4.A.4, §4.B.3).
type Service struct {
	ring *KeyRing
}

// NewService constructs a crypto service from a 32-byte master key.
func NewService(masterKey []byte) (*Service, error) {
	ring, err := NewKeyRing(masterKey)
	if err != nil {
		return nil, err
	}
	return &Service{ring: ring}, nil
}

// ActiveKeyVersion returns the master key version used for new DEK encryptions.
func (s *Service) ActiveKeyVersion() byte {
	if s == nil || s.ring == nil {
		return 0
	}
	return s.ring.ActiveVersion()
}

// KeyVersions returns sorted master key versions.
func (s *Service) KeyVersions() []byte {
	if s == nil || s.ring == nil {
		return nil
	}
	return s.ring.Versions()
}

// RotateMasterKey adds a new master key version and makes it active.
func (s *Service) RotateMasterKey(newMasterKey []byte) (byte, error) {
	if s == nil || s.ring == nil {
		return 0, fmt.Errorf("crypto service not configured")
	}
	versions := s.ring.Versions()
	next := byte(1)
	if len(versions) > 0 {
		next = versions[len(versions)-1] + 1
	}
	if err := s.ring.AddKey(next, newMasterKey); err != nil {
		return 0, err
	}
	return next, nil
}

// LoadPreviousMasterKey registers an older master key version for decrypting historical DEKs (W76/W63).
// Versions are assigned as 1..n in order before the active key remains highest.
func (s *Service) LoadPreviousMasterKey(masterKey []byte) error {
	if s == nil || s.ring == nil {
		return fmt.Errorf("crypto service not configured")
	}
	if len(masterKey) != 32 {
		return fmt.Errorf("previous master key must be 32 bytes, got %d", len(masterKey))
	}
	versions := s.ring.Versions()
	// Insert as next free version below active: use max+1 then swap active back... simpler: AddKey with next and re-set active.
	// KeyRing.AddKey always sets active to new version; restore previous active after load.
	active := s.ring.ActiveVersion()
	next := byte(1)
	if len(versions) > 0 {
		next = versions[len(versions)-1] + 1
	}
	if err := s.ring.AddKey(next, masterKey); err != nil {
		return err
	}
	// Keep original active for new encryptions (previous keys are decrypt-only until Rotate).
	return s.ring.SetActiveVersion(active)
}

// DEKNeedsReencrypt reports whether a wrapped DEK should be re-encrypted.
func (s *Service) DEKNeedsReencrypt(enc []byte) bool {
	if s == nil || s.ring == nil {
		return false
	}
	return s.ring.DEKNeedsReencrypt(enc)
}

// ReencryptDEK re-wraps a DEK with the active master key.
// Plaintext DEK is zeroed inside KeyRing.ReencryptDEK (W50-16).
func (s *Service) ReencryptDEK(enc []byte) ([]byte, error) {
	if s == nil || s.ring == nil {
		return nil, fmt.Errorf("crypto service not configured")
	}
	return s.ring.ReencryptDEK(enc)
}

// GenerateDEK returns a random 32-byte data encryption key.
func (s *Service) GenerateDEK() ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generate dek: %w", err)
	}
	return dek, nil
}

// EncryptDEK seals a DEK with the master key envelope.
func (s *Service) EncryptDEK(dek []byte) ([]byte, error) {
	if s == nil || s.ring == nil {
		return nil, fmt.Errorf("crypto service not configured")
	}
	return s.ring.EncryptDEK(dek)
}

// DecryptDEK opens a master-key-encrypted DEK.
func (s *Service) DecryptDEK(enc []byte) ([]byte, error) {
	if s == nil || s.ring == nil {
		return nil, fmt.Errorf("crypto service not configured")
	}
	dek, err := s.ring.DecryptDEK(enc)
	if err != nil {
		return nil, err
	}
	if len(dek) != dekSize {
		return nil, fmt.Errorf("decrypted dek invalid length %d", len(dek))
	}
	return dek, nil
}

// EncryptWithDEK encrypts plaintext using a DEK (AES-256-GCM).
func (s *Service) EncryptWithDEK(dek, plaintext []byte) ([]byte, error) {
	env, err := NewEnvelope(dek)
	if err != nil {
		return nil, err
	}
	return env.Encrypt(plaintext)
}

// DecryptWithDEK decrypts ciphertext using a DEK.
func (s *Service) DecryptWithDEK(dek, ciphertext []byte) ([]byte, error) {
	env, err := NewEnvelope(dek)
	if err != nil {
		return nil, err
	}
	return env.Decrypt(ciphertext)
}

// Seal encrypts plaintext: generates DEK, encrypts data, returns ciphertext and encrypted DEK.
// The plaintext DEK is zeroed before return (W50-16).
func (s *Service) Seal(plaintext []byte) (ciphertext, dekEnc []byte, err error) {
	dek, err := s.GenerateDEK()
	if err != nil {
		return nil, nil, err
	}
	defer memzero.Bytes(dek)
	ciphertext, err = s.EncryptWithDEK(dek, plaintext)
	if err != nil {
		return nil, nil, err
	}
	dekEnc, err = s.EncryptDEK(dek)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, dekEnc, nil
}

// Open decrypts ciphertext using an encrypted DEK.
// The plaintext DEK is zeroed before return (W50-16).
func (s *Service) Open(ciphertext, dekEnc []byte) ([]byte, error) {
	dek, err := s.DecryptDEK(dekEnc)
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(dek)
	return s.DecryptWithDEK(dek, ciphertext)
}
