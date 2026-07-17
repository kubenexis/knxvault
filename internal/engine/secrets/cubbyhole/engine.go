// Package cubbyhole implements per-token private KV storage (M-WRAP-1).
package cubbyhole

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
)

const engineName = "cubbyhole"
const pathPrefix = "cubbyhole/"

// Engine stores secrets scoped to a token ID (hash).
type Engine struct {
	repo   repository.SecretRepository
	crypto *crypto.Service
}

// NewEngine constructs a cubbyhole engine.
func NewEngine(repo repository.SecretRepository, cryptoSvc *crypto.Service) *Engine {
	return &Engine{repo: repo, crypto: cryptoSvc}
}

// Name returns the engine name.
func (e *Engine) Name() string { return engineName }

func storagePath(tokenID, path string) string {
	path = strings.TrimPrefix(strings.TrimSpace(path), "/")
	return pathPrefix + tokenID + "/" + path
}

// Put stores data under the token-private path.
func (e *Engine) Put(ctx context.Context, tokenID, path string, data map[string]any) error {
	if e == nil || e.repo == nil || e.crypto == nil {
		return common.New(common.ErrCodeInternal, "cubbyhole not configured")
	}
	if tokenID == "" {
		return common.New(common.ErrCodeUnauthorized, "token id required")
	}
	if path == "" || strings.Contains(path, "..") {
		return common.New(common.ErrCodeValidation, "invalid cubbyhole path")
	}
	if len(data) == 0 {
		return common.New(common.ErrCodeValidation, "data required")
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return common.Wrap(common.ErrCodeInternal, "marshal", err)
	}
	dataEnc, dekEnc, err := e.crypto.Seal(raw)
	if err != nil {
		return common.Wrap(common.ErrCodeInternal, "encrypt", err)
	}
	sv := &domainsecrets.SecretVersion{
		ID:        uuid.New(),
		Path:      storagePath(tokenID, path),
		DataEnc:   dataEnc,
		DEKEnc:    dekEnc,
		CreatedAt: time.Now().UTC(),
		Labels:    map[string]string{"engine": engineName, "token_id": tokenID},
	}
	_, err = e.repo.PutAtomic(ctx, sv, nil, 1)
	return err
}

// Get returns data for a token-private path.
func (e *Engine) Get(ctx context.Context, tokenID, path string) (map[string]any, error) {
	if e == nil || e.repo == nil || e.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "cubbyhole not configured")
	}
	if tokenID == "" {
		return nil, common.New(common.ErrCodeUnauthorized, "token id required")
	}
	sv, err := e.repo.GetLatest(ctx, storagePath(tokenID, path))
	if err != nil {
		return nil, err
	}
	plain, err := e.crypto.Open(sv.DataEnc, sv.DEKEnc)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "decrypt", err)
	}
	var data map[string]any
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "unmarshal", err)
	}
	return data, nil
}

// Delete removes a cubbyhole entry.
func (e *Engine) Delete(ctx context.Context, tokenID, path string) error {
	if e == nil || e.repo == nil {
		return common.New(common.ErrCodeInternal, "cubbyhole not configured")
	}
	sv, err := e.repo.GetLatest(ctx, storagePath(tokenID, path))
	if err != nil {
		return err
	}
	return e.repo.DestroyVersion(ctx, sv.Path, sv.Version)
}

// WipeToken deletes all cubbyhole entries for a token (best-effort list prefix).
func (e *Engine) WipeToken(ctx context.Context, tokenID string) error {
	if e == nil || e.repo == nil || tokenID == "" {
		return nil
	}
	prefix := pathPrefix + tokenID + "/"
	list, err := e.repo.ListByPath(ctx, prefix)
	if err != nil {
		return err
	}
	seen := map[string]int{}
	for _, sv := range list {
		if sv == nil {
			continue
		}
		// Keep highest version per path for destroy
		if v, ok := seen[sv.Path]; !ok || sv.Version > v {
			seen[sv.Path] = sv.Version
		}
	}
	var first error
	for path, ver := range seen {
		if err := e.repo.DestroyVersion(ctx, path, ver); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// PutWrap stores a one-shot wrapping payload under a synthetic token id (wrapping token hash).
func (e *Engine) PutWrap(ctx context.Context, wrapTokenID, path string, data map[string]any, ttl time.Duration) error {
	if err := e.Put(ctx, wrapTokenID, path, data); err != nil {
		return err
	}
	// TTL is enforced by wrapping service via wrap record expiry, not storage TTL.
	_ = ttl
	return nil
}

// FullPath exposes storage path for tests.
func FullPath(tokenID, path string) string {
	return storagePath(tokenID, path)
}

// Ensure path helper used by tests.
func ValidatePath(path string) error {
	if path == "" || strings.Contains(path, "..") {
		return fmt.Errorf("invalid path")
	}
	return nil
}
