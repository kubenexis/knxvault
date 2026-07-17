// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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

const defaultMaxVersions = 10

// PutOptions controls secret writes.
type PutOptions struct {
	TTL         string
	CasVersion  *int
	MaxVersions int
	Labels      map[string]string
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

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "marshal secret data", err)
	}

	dataEnc, dekEnc, err := e.crypto.Seal(payload)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "encrypt secret data", err)
	}

	now := time.Now().UTC()
	sv := &domainsecrets.SecretVersion{
		ID:        uuid.New(),
		Path:      path,
		DataEnc:   dataEnc,
		DEKEnc:    dekEnc,
		CreatedAt: now,
		Labels:    opts.Labels,
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

	maxVersions := opts.MaxVersions
	if maxVersions <= 0 {
		maxVersions = defaultMaxVersions
	}

	version, err := e.repo.PutAtomic(ctx, sv, opts.CasVersion, maxVersions)
	if err != nil {
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
	Labels    map[string]string
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
		Labels:    sv.Labels,
	}
	if sv.TTLSeconds != nil {
		result.TTL = fmt.Sprintf("%ds", *sv.TTLSeconds)
	}
	return result, nil
}

// VersionMetadata describes a secret version without decrypted data.
type VersionMetadata struct {
	Version   int
	CreatedAt time.Time
	Destroyed bool
	TTL       string
}

// PathMetadata summarizes versions for a secret path.
type PathMetadata struct {
	Path           string
	CurrentVersion int
	Versions       []VersionMetadata
	MaxVersions    int
	Labels         map[string]string
}

// DestroyVersion marks a specific version as destroyed.
func (e *KVV2Engine) DestroyVersion(ctx context.Context, path string, version int) error {
	if e.repo == nil {
		return common.New(common.ErrCodeInternal, "kv engine not fully configured")
	}
	if path == "" || version < 1 {
		return common.New(common.ErrCodeValidation, "path and version are required")
	}
	return e.repo.DestroyVersion(ctx, path, version)
}

// ListPaths returns unique secret paths under a prefix.
func (e *KVV2Engine) ListPaths(ctx context.Context, prefix string) ([]string, error) {
	if e.repo == nil {
		return nil, common.New(common.ErrCodeInternal, "kv engine not fully configured")
	}
	versions, err := e.repo.ListByPath(ctx, prefix)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var paths []string
	for _, sv := range versions {
		if _, ok := seen[sv.Path]; ok {
			continue
		}
		seen[sv.Path] = struct{}{}
		paths = append(paths, sv.Path)
	}
	return paths, nil
}

// ListVersions returns metadata for all versions at a path.
func (e *KVV2Engine) ListVersions(ctx context.Context, path string) ([]VersionMetadata, error) {
	if e.repo == nil {
		return nil, common.New(common.ErrCodeInternal, "kv engine not fully configured")
	}
	versions, err := e.repo.ListByPath(ctx, path)
	if err != nil {
		return nil, err
	}
	var out []VersionMetadata
	for _, sv := range versions {
		if sv.Path != path {
			continue
		}
		meta := VersionMetadata{
			Version:   sv.Version,
			CreatedAt: sv.CreatedAt,
			Destroyed: sv.Destroyed,
		}
		if sv.TTLSeconds != nil {
			meta.TTL = fmt.Sprintf("%ds", *sv.TTLSeconds)
		}
		out = append(out, meta)
	}
	if len(out) == 0 {
		return nil, common.New(common.ErrCodeNotFound, "secret path not found")
	}
	return out, nil
}

// GetMetadata returns metadata for the latest or specific version.
func (e *KVV2Engine) GetMetadata(ctx context.Context, path string, version int) (*PathMetadata, error) {
	if e.repo == nil {
		return nil, common.New(common.ErrCodeInternal, "kv engine not fully configured")
	}
	versions, err := e.ListVersions(ctx, path)
	if err != nil {
		return nil, err
	}
	meta := &PathMetadata{
		Path:        path,
		MaxVersions: defaultMaxVersions,
		Versions:    versions,
	}
	for _, v := range versions {
		if v.Version > meta.CurrentVersion && !v.Destroyed {
			meta.CurrentVersion = v.Version
		}
	}
	if version > 0 {
		found := false
		for _, v := range versions {
			if v.Version == version {
				found = true
				break
			}
		}
		if !found {
			return nil, common.New(common.ErrCodeNotFound, "secret version not found")
		}
	}
	targetVersion := meta.CurrentVersion
	if version > 0 {
		targetVersion = version
	}
	if targetVersion > 0 {
		if sv, err := e.repo.GetVersion(ctx, path, targetVersion); err == nil {
			meta.Labels = sv.Labels
		}
	}
	return meta, nil
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
