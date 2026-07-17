// Package transit implements Encryption-as-a-Service (M-TRANSIT-1).
package transit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/crypto/memzero"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
)

const (
	engineName   = "transit"
	keysPrefix   = "transit/keys/"
	cipherPrefix = "v"
)

// KeyMeta is public metadata for a transit key (no raw material).
type KeyMeta struct {
	Name            string    `json:"name"`
	Type            string    `json:"type"` // aes256-gcm96
	LatestVersion   int       `json:"latest_version"`
	MinDecryptVer   int       `json:"min_decryption_version"`
	CreatedAt       time.Time `json:"created_at"`
	SupportsEncrypt bool      `json:"supports_encryption"`
	SupportsSign    bool      `json:"supports_signing"`
}

type keyRecord struct {
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	LatestVersion int               `json:"latest_version"`
	MinDecryptVer int               `json:"min_decryption_version"`
	CreatedAt     time.Time         `json:"created_at"`
	Versions      map[string][]byte `json:"versions"` // version -> DEKEnc (wrapped)
}

// Engine provides transit encrypt/decrypt/sign/hmac/rotate.
type Engine struct {
	mu     sync.RWMutex
	repo   repository.SecretRepository
	crypto *crypto.Service
	// memory fallback when repo nil (tests)
	mem map[string]*keyRecord
}

// NewEngine constructs a transit engine. Repo may be nil for pure memory tests with crypto only.
func NewEngine(repo repository.SecretRepository, cryptoSvc *crypto.Service) *Engine {
	return &Engine{repo: repo, crypto: cryptoSvc, mem: make(map[string]*keyRecord)}
}

// Name returns engine name.
func (e *Engine) Name() string { return engineName }

// CreateKey creates a new AES-256 transit key.
func (e *Engine) CreateKey(ctx context.Context, name string) (*KeyMeta, error) {
	if e == nil || e.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "transit not configured")
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "..") {
		return nil, common.New(common.ErrCodeValidation, "invalid key name")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.loadLocked(ctx, name); err == nil {
		return nil, common.New(common.ErrCodeValidation, "key already exists")
	}
	dek, err := e.crypto.GenerateDEK()
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(dek)
	dekEnc, err := e.crypto.EncryptDEK(dek)
	if err != nil {
		return nil, err
	}
	rec := &keyRecord{
		Name:          name,
		Type:          "aes256-gcm96",
		LatestVersion: 1,
		MinDecryptVer: 1,
		CreatedAt:     time.Now().UTC(),
		Versions:      map[string][]byte{"1": dekEnc},
	}
	if err := e.saveLocked(ctx, rec); err != nil {
		return nil, err
	}
	return metaOf(rec), nil
}

// ReadKey returns metadata without key material.
func (e *Engine) ReadKey(ctx context.Context, name string) (*KeyMeta, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rec, err := e.loadLocked(ctx, name)
	if err != nil {
		return nil, err
	}
	return metaOf(rec), nil
}

// RotateKey adds a new key version.
func (e *Engine) RotateKey(ctx context.Context, name string) (*KeyMeta, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, err := e.loadLocked(ctx, name)
	if err != nil {
		return nil, err
	}
	dek, err := e.crypto.GenerateDEK()
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(dek)
	dekEnc, err := e.crypto.EncryptDEK(dek)
	if err != nil {
		return nil, err
	}
	rec.LatestVersion++
	rec.Versions[strconv.Itoa(rec.LatestVersion)] = dekEnc
	if err := e.saveLocked(ctx, rec); err != nil {
		return nil, err
	}
	return metaOf(rec), nil
}

// Encrypt encrypts plaintext with the latest (or specified) key version.
func (e *Engine) Encrypt(ctx context.Context, name string, plaintext []byte, keyVersion int) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rec, err := e.loadLocked(ctx, name)
	if err != nil {
		return "", err
	}
	ver := rec.LatestVersion
	if keyVersion > 0 {
		ver = keyVersion
	}
	dek, err := e.dekFor(rec, ver)
	if err != nil {
		return "", err
	}
	defer memzero.Bytes(dek)
	ct, err := e.crypto.EncryptWithDEK(dek, plaintext)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%d:%s", cipherPrefix, ver, base64.RawStdEncoding.EncodeToString(ct)), nil
}

// Decrypt decrypts a transit ciphertext string.
func (e *Engine) Decrypt(ctx context.Context, name, ciphertext string) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rec, err := e.loadLocked(ctx, name)
	if err != nil {
		return nil, err
	}
	ver, raw, err := parseCipher(ciphertext)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "ciphertext", err)
	}
	if ver < rec.MinDecryptVer {
		return nil, common.New(common.ErrCodeForbidden, "key version below minimum")
	}
	dek, err := e.dekFor(rec, ver)
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(dek)
	return e.crypto.DecryptWithDEK(dek, raw)
}

// Rewrap decrypts with source version and re-encrypts with latest.
func (e *Engine) Rewrap(ctx context.Context, name, ciphertext string) (string, error) {
	pt, err := e.Decrypt(ctx, name, ciphertext)
	if err != nil {
		return "", err
	}
	return e.Encrypt(ctx, name, pt, 0)
}

// HMAC computes HMAC-SHA256 with the transit key material.
func (e *Engine) HMAC(ctx context.Context, name string, input []byte, keyVersion int) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rec, err := e.loadLocked(ctx, name)
	if err != nil {
		return "", err
	}
	ver := rec.LatestVersion
	if keyVersion > 0 {
		ver = keyVersion
	}
	dek, err := e.dekFor(rec, ver)
	if err != nil {
		return "", err
	}
	defer memzero.Bytes(dek)
	mac := hmac.New(sha256.New, dek)
	_, _ = mac.Write(input)
	return "hmac:v" + strconv.Itoa(ver) + ":" + base64.RawStdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Sign produces an HMAC-based signature (symmetric transit keys).
func (e *Engine) Sign(ctx context.Context, name string, input []byte, keyVersion int) (string, error) {
	return e.HMAC(ctx, name, input, keyVersion)
}

// Verify checks an HMAC signature.
func (e *Engine) Verify(ctx context.Context, name string, input []byte, signature string) (bool, error) {
	// Parse version from signature if present.
	ver := 0
	if strings.HasPrefix(signature, "hmac:v") {
		rest := strings.TrimPrefix(signature, "hmac:v")
		if i := strings.IndexByte(rest, ':'); i > 0 {
			ver, _ = strconv.Atoi(rest[:i])
		}
	}
	got, err := e.HMAC(ctx, name, input, ver)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(got), []byte(signature)), nil
}

func (e *Engine) dekFor(rec *keyRecord, ver int) ([]byte, error) {
	enc, ok := rec.Versions[strconv.Itoa(ver)]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "key version not found")
	}
	return e.crypto.DecryptDEK(enc)
}

func parseCipher(s string) (int, []byte, error) {
	if !strings.HasPrefix(s, cipherPrefix) {
		return 0, nil, fmt.Errorf("missing version prefix")
	}
	rest := s[len(cipherPrefix):]
	i := strings.IndexByte(rest, ':')
	if i <= 0 {
		return 0, nil, fmt.Errorf("invalid format")
	}
	ver, err := strconv.Atoi(rest[:i])
	if err != nil {
		return 0, nil, err
	}
	raw, err := base64.RawStdEncoding.DecodeString(rest[i+1:])
	if err != nil {
		// try StdEncoding
		raw, err = base64.StdEncoding.DecodeString(rest[i+1:])
		if err != nil {
			return 0, nil, err
		}
	}
	return ver, raw, nil
}

func metaOf(rec *keyRecord) *KeyMeta {
	return &KeyMeta{
		Name:            rec.Name,
		Type:            rec.Type,
		LatestVersion:   rec.LatestVersion,
		MinDecryptVer:   rec.MinDecryptVer,
		CreatedAt:       rec.CreatedAt,
		SupportsEncrypt: true,
		SupportsSign:    true,
	}
}

func (e *Engine) loadLocked(ctx context.Context, name string) (*keyRecord, error) {
	if e.repo != nil {
		sv, err := e.repo.GetLatest(ctx, keysPrefix+name)
		if err != nil {
			// fallback mem
			if rec, ok := e.mem[name]; ok {
				return rec, nil
			}
			return nil, err
		}
		plain, err := e.crypto.Open(sv.DataEnc, sv.DEKEnc)
		if err != nil {
			return nil, err
		}
		var rec keyRecord
		if err := json.Unmarshal(plain, &rec); err != nil {
			return nil, err
		}
		e.mem[name] = &rec
		return &rec, nil
	}
	rec, ok := e.mem[name]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "transit key not found")
	}
	return rec, nil
}

func (e *Engine) saveLocked(ctx context.Context, rec *keyRecord) error {
	e.mem[rec.Name] = rec
	if e.repo == nil {
		return nil
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	dataEnc, dekEnc, err := e.crypto.Seal(raw)
	if err != nil {
		return err
	}
	sv := &domainsecrets.SecretVersion{
		ID:        uuid.New(),
		Path:      keysPrefix + rec.Name,
		DataEnc:   dataEnc,
		DEKEnc:    dekEnc,
		CreatedAt: time.Now().UTC(),
		Labels:    map[string]string{"engine": engineName},
	}
	_, err = e.repo.PutAtomic(ctx, sv, nil, 5)
	return err
}

// RandomNonce helper for tests.
func RandomNonce(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}
