package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
)

const dekSize = 32

// Service provides envelope encryption for data and DEKs (LLD §4.A.4, §4.B.3).
type Service struct {
	master *Envelope
}

// NewService constructs a crypto service from a 32-byte master key.
func NewService(masterKey []byte) (*Service, error) {
	env, err := NewEnvelope(masterKey)
	if err != nil {
		return nil, err
	}
	return &Service{master: env}, nil
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
	if len(dek) != dekSize {
		return nil, fmt.Errorf("dek must be %d bytes, got %d", dekSize, len(dek))
	}
	return s.master.Encrypt(dek)
}

// DecryptDEK opens a master-key-encrypted DEK.
func (s *Service) DecryptDEK(enc []byte) ([]byte, error) {
	dek, err := s.master.Decrypt(enc)
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
func (s *Service) Seal(plaintext []byte) (ciphertext, dekEnc []byte, err error) {
	dek, err := s.GenerateDEK()
	if err != nil {
		return nil, nil, err
	}
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
func (s *Service) Open(ciphertext, dekEnc []byte) ([]byte, error) {
	dek, err := s.DecryptDEK(dekEnc)
	if err != nil {
		return nil, err
	}
	return s.DecryptWithDEK(dek, ciphertext)
}
