// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package cubbyhole implements per-token private KV storage (M-WRAP-1 / W74).
package cubbyhole

import (
	"context"
	"encoding/json"
	"path"
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

// NormalizePath cleans and validates a relative cubbyhole path.
func NormalizePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", common.New(common.ErrCodeValidation, "invalid cubbyhole path")
	}
	// Reject any ".." segment before clean so traversal cannot be normalized away.
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return "", common.New(common.ErrCodeValidation, "invalid cubbyhole path")
		}
	}
	cleaned := path.Clean("/" + p)
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return "", common.New(common.ErrCodeValidation, "invalid cubbyhole path")
	}
	return cleaned, nil
}

func storagePath(tokenID, p string) (string, error) {
	np, err := NormalizePath(p)
	if err != nil {
		return "", err
	}
	return pathPrefix + tokenID + "/" + np, nil
}

// Put stores data under the token-private path.
func (e *Engine) Put(ctx context.Context, tokenID, p string, data map[string]any) error {
	if e == nil || e.repo == nil || e.crypto == nil {
		return common.New(common.ErrCodeInternal, "cubbyhole not configured")
	}
	if tokenID == "" {
		return common.New(common.ErrCodeUnauthorized, "token id required")
	}
	sp, err := storagePath(tokenID, p)
	if err != nil {
		return err
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
		Path:      sp,
		DataEnc:   dataEnc,
		DEKEnc:    dekEnc,
		CreatedAt: time.Now().UTC(),
		Labels:    map[string]string{"engine": engineName, "token_id": tokenID},
	}
	_, err = e.repo.PutAtomic(ctx, sv, nil, 1)
	return err
}

// Get returns data for a token-private path.
func (e *Engine) Get(ctx context.Context, tokenID, p string) (map[string]any, error) {
	if e == nil || e.repo == nil || e.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "cubbyhole not configured")
	}
	if tokenID == "" {
		return nil, common.New(common.ErrCodeUnauthorized, "token id required")
	}
	sp, err := storagePath(tokenID, p)
	if err != nil {
		return nil, err
	}
	sv, err := e.repo.GetLatest(ctx, sp)
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

// Delete removes a cubbyhole entry (all versions for that path).
func (e *Engine) Delete(ctx context.Context, tokenID, p string) error {
	if e == nil || e.repo == nil {
		return common.New(common.ErrCodeInternal, "cubbyhole not configured")
	}
	sp, err := storagePath(tokenID, p)
	if err != nil {
		return err
	}
	return destroyAllVersions(ctx, e.repo, sp)
}

// WipeToken deletes all cubbyhole entries for a token (all versions).
func (e *Engine) WipeToken(ctx context.Context, tokenID string) error {
	if e == nil || e.repo == nil || tokenID == "" {
		return nil
	}
	prefix := pathPrefix + tokenID + "/"
	list, err := e.repo.ListByPath(ctx, prefix)
	if err != nil {
		return err
	}
	// Destroy every version of every path under the token prefix.
	var first error
	seen := map[string]map[int]struct{}{}
	for _, sv := range list {
		if sv == nil {
			continue
		}
		if seen[sv.Path] == nil {
			seen[sv.Path] = map[int]struct{}{}
		}
		if _, ok := seen[sv.Path][sv.Version]; ok {
			continue
		}
		seen[sv.Path][sv.Version] = struct{}{}
		if err := e.repo.DestroyVersion(ctx, sv.Path, sv.Version); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func destroyAllVersions(ctx context.Context, repo repository.SecretRepository, sp string) error {
	list, err := repo.ListByPath(ctx, sp)
	if err != nil {
		// Fallback: destroy latest only
		sv, gerr := repo.GetLatest(ctx, sp)
		if gerr != nil {
			return gerr
		}
		return repo.DestroyVersion(ctx, sv.Path, sv.Version)
	}
	var first error
	for _, sv := range list {
		if sv == nil || sv.Path != sp {
			continue
		}
		if err := repo.DestroyVersion(ctx, sv.Path, sv.Version); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// FullPath exposes storage path for tests.
func FullPath(tokenID, p string) string {
	sp, err := storagePath(tokenID, p)
	if err != nil {
		return ""
	}
	return sp
}

// ValidatePath is an alias for NormalizePath for tests.
func ValidatePath(p string) error {
	_, err := NormalizePath(p)
	return err
}
