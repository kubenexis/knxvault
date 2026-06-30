// Package secrets implements the KVv2 secrets engine (LLD §4.B).
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/utils"
)

const engineName = "kv"

// KVV2Engine stores versioned encrypted secrets.
type KVV2Engine struct {
	repo   repository.SecretRepository
	crypto *crypto.Service
}

// NewKVV2Engine constructs a KVv2 engine.
func NewKVV2Engine(repo repository.SecretRepository, cryptoSvc *crypto.Service) *KVV2Engine {
	return &KVV2Engine{repo: repo, crypto: cryptoSvc}
}

// Name returns the engine identifier.
func (e *KVV2Engine) Name() string {
	return engineName
}

// PutOptions controls secret writes.
type PutOptions struct {
	TTL        string
	CasVersion *int
}

// PutResult contains write metadata.
type PutResult struct {
	Version int
}

// Put stores a new secret version.
func (e *KVV2Engine) Put(ctx context.Context, path string, data map[string]any, opts PutOptions) (*PutResult, error) {
	if e.repo == nil || e.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "kv engine not fully configured")
	}
	if path == "" {
		return nil, common.New(common.ErrCodeValidation, "secret path is required")
	}
	if len(data) == 0 {
		return nil, common.New(common.ErrCodeValidation, "secret data is required")
	}

	if opts.CasVersion != nil {
		latest, err := e.repo.GetLatest(ctx, path)
		if err != nil {
			return nil, err
		}
		if latest.Version != *opts.CasVersion {
			return nil, common.New(common.ErrCodeValidation, "cas version mismatch")
		}
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "marshal secret data", err)
	}

	dataEnc, dekEnc, err := e.crypto.Seal(payload)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "encrypt secret data", err)
	}

	version, err := e.repo.NextVersion(ctx, path)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	sv := &domainsecrets.SecretVersion{
		ID:        uuid.New(),
		Path:      path,
		Version:   version,
		DataEnc:   dataEnc,
		DEKEnc:    dekEnc,
		CreatedAt: now,
	}

	if opts.TTL != "" {
		ttl, err := utils.ParseTTL(opts.TTL)
		if err != nil {
			return nil, common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
		}
		ttlSeconds := int(ttl.Seconds())
		sv.TTLSeconds = &ttlSeconds
		expires := now.Add(ttl)
		sv.ExpiresAt = &expires
	}

	if err := e.repo.SaveVersion(ctx, sv); err != nil {
		return nil, err
	}

	return &PutResult{Version: version}, nil
}

// GetResult contains secret data and metadata.
type GetResult struct {
	Data      map[string]any
	Version   int
	CreatedAt time.Time
	TTL       string
}

// Get returns the latest secret version.
func (e *KVV2Engine) Get(ctx context.Context, path string) (*GetResult, error) {
	return e.GetVersion(ctx, path, 0)
}

// GetVersion returns a specific version (0 = latest).
func (e *KVV2Engine) GetVersion(ctx context.Context, path string, version int) (*GetResult, error) {
	if e.repo == nil || e.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "kv engine not fully configured")
	}

	var (
		sv  *domainsecrets.SecretVersion
		err error
	)
	if version <= 0 {
		sv, err = e.repo.GetLatest(ctx, path)
	} else {
		sv, err = e.repo.GetVersion(ctx, path, version)
	}
	if err != nil {
		return nil, err
	}
	if sv.Destroyed {
		return nil, common.New(common.ErrCodeNotFound, "secret version destroyed")
	}
	if sv.ExpiresAt != nil && time.Now().UTC().After(*sv.ExpiresAt) {
		return nil, common.New(common.ErrCodeNotFound, "secret version expired")
	}

	plain, err := e.crypto.Open(sv.DataEnc, sv.DEKEnc)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "decrypt secret data", err)
	}

	var data map[string]any
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "unmarshal secret data", err)
	}

	result := &GetResult{
		Data:      data,
		Version:   sv.Version,
		CreatedAt: sv.CreatedAt,
	}
	if sv.TTLSeconds != nil {
		result.TTL = fmt.Sprintf("%ds", *sv.TTLSeconds)
	}
	return result, nil
}

// Delete soft-deletes the latest secret version.
func (e *KVV2Engine) Delete(ctx context.Context, path string) error {
	if e.repo == nil || e.crypto == nil {
		return common.New(common.ErrCodeInternal, "kv engine not fully configured")
	}

	latest, err := e.repo.GetLatest(ctx, path)
	if err != nil {
		return err
	}

	destroyed := &domainsecrets.SecretVersion{
		ID:        uuid.New(),
		Path:      path,
		Version:   latest.Version + 1,
		DataEnc:   []byte{0},
		DEKEnc:    latest.DEKEnc,
		CreatedAt: time.Now().UTC(),
		Destroyed: true,
	}
	return e.repo.SaveVersion(ctx, destroyed)
}
