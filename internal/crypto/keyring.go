package crypto

import (
	"fmt"
	"sort"
	"sync"

	"github.com/kubenexis/knxvault/internal/crypto/memzero"
)

const dekVersionPrefixSize = 1

// KeyRing holds versioned master keys for envelope DEK wrapping.
type KeyRing struct {
	mu     sync.RWMutex
	keys   map[byte][]byte
	active byte
	legacy bool // true when only version 1 exists and DEKs omit version prefix
}

// NewKeyRing creates a keyring with a single active key at version 1.
func NewKeyRing(masterKey []byte) (*KeyRing, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	key := append([]byte(nil), masterKey...)
	return &KeyRing{
		keys:   map[byte][]byte{1: key},
		active: 1,
		legacy: true,
	}, nil
}

// ActiveVersion returns the key version used for new DEK encryptions.
func (k *KeyRing) ActiveVersion() byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.active
}

// AddKey registers a new master key version and makes it active.
func (k *KeyRing) AddKey(version byte, masterKey []byte) error {
	if version == 0 {
		return fmt.Errorf("key version must be > 0")
	}
	if len(masterKey) != 32 {
		return fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, exists := k.keys[version]; exists {
		return fmt.Errorf("key version %d already exists", version)
	}
	k.keys[version] = append([]byte(nil), masterKey...)
	k.active = version
	k.legacy = false
	return nil
}

// Versions returns sorted key versions.
func (k *KeyRing) Versions() []byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]byte, 0, len(k.keys))
	for v := range k.keys {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (k *KeyRing) envelope(version byte) (*Envelope, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, ok := k.keys[version]
	if !ok {
		return nil, fmt.Errorf("unknown key version %d", version)
	}
	return NewEnvelope(key)
}

// EncryptDEK seals a DEK with the active master key version.
func (k *KeyRing) EncryptDEK(dek []byte) ([]byte, error) {
	if len(dek) != dekSize {
		return nil, fmt.Errorf("dek must be %d bytes, got %d", dekSize, len(dek))
	}
	k.mu.RLock()
	version := k.active
	legacy := k.legacy
	k.mu.RUnlock()

	env, err := k.envelope(version)
	if err != nil {
		return nil, err
	}
	enc, err := env.Encrypt(dek)
	if err != nil {
		return nil, err
	}
	if legacy && version == 1 {
		return enc, nil
	}
	out := make([]byte, dekVersionPrefixSize+len(enc))
	out[0] = version
	copy(out[1:], enc)
	return out, nil
}

// DecryptDEK opens a master-key-encrypted DEK, trying all known versions.
func (k *KeyRing) DecryptDEK(enc []byte) ([]byte, error) {
	if len(enc) == 0 {
		return nil, fmt.Errorf("empty encrypted dek")
	}

	k.mu.RLock()
	versions := make([]byte, 0, len(k.keys))
	for v := range k.keys {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	k.mu.RUnlock()

	// Versioned DEKs prefix a 1-byte key version before the GCM blob (nonce + ciphertext + tag).
	const minVersionedLen = dekVersionPrefixSize + 13 + dekSize
	if len(enc) >= minVersionedLen {
		if version := enc[0]; version > 0 && versionKnown(versions, version) {
			if env, err := k.envelope(version); err == nil {
				if dek, err := env.Decrypt(enc[1:]); err == nil && len(dek) == dekSize {
					return dek, nil
				}
			}
		}
	}

	var lastErr error
	for _, version := range versions {
		env, err := k.envelope(version)
		if err != nil {
			continue
		}
		dek, err := env.Decrypt(enc)
		if err != nil {
			lastErr = err
			continue
		}
		if len(dek) != dekSize {
			lastErr = fmt.Errorf("decrypted dek invalid length %d", len(dek))
			continue
		}
		return dek, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("unable to decrypt dek")
}

// DEKNeedsReencrypt reports whether enc uses an older key version than active.
func (k *KeyRing) DEKNeedsReencrypt(enc []byte) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.legacy && k.active == 1 {
		return false
	}
	if version, ok := k.versionedDEKVersionLocked(enc); ok {
		return version != k.active
	}
	// Unversioned legacy ciphertext was sealed before key versioning was enabled.
	return true
}

func (k *KeyRing) versionedDEKVersionLocked(enc []byte) (byte, bool) {
	const minVersionedLen = dekVersionPrefixSize + 13 + dekSize
	if len(enc) < minVersionedLen {
		return 0, false
	}
	version := enc[0]
	if version == 0 {
		return 0, false
	}
	key, ok := k.keys[version]
	if !ok {
		return 0, false
	}
	env, err := NewEnvelope(key)
	if err != nil {
		return 0, false
	}
	dek, err := env.Decrypt(enc[1:])
	if err != nil || len(dek) != dekSize {
		return 0, false
	}
	return version, true
}

// ReencryptDEK decrypts and re-encrypts with the active key.
func (k *KeyRing) ReencryptDEK(enc []byte) ([]byte, error) {
	dek, err := k.DecryptDEK(enc)
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(dek)
	return k.EncryptDEK(dek)
}

func versionKnown(versions []byte, version byte) bool {
	for _, v := range versions {
		if v == version {
			return true
		}
	}
	return false
}
