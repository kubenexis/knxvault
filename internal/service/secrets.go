// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/cache"
	"github.com/kubenexis/knxvault/internal/domain/common"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
	"github.com/kubenexis/knxvault/internal/tenant"
)

// SecretsService coordinates KV secret operations with audit logging.
type SecretsService struct {
	engine     *secretsengine.KVV2Engine
	audit      *auditsvc.Service
	tenantMode bool
	cache      cache.Store
	cacheGen   sync.Map
}

// NewSecretsService constructs a secrets service.
func NewSecretsService(engine *secretsengine.KVV2Engine, audit *auditsvc.Service) *SecretsService {
	return &SecretsService{engine: engine, audit: audit}
}

// SetTenantMode enables tenant path scoping (W32-04).
func (s *SecretsService) SetTenantMode(enabled bool) {
	if s != nil {
		s.tenantMode = enabled
	}
}

// SetCache configures optional read-through caching (W33-01–02).
func (s *SecretsService) SetCache(store cache.Store) {
	if s != nil {
		s.cache = store
	}
}

func (s *SecretsService) cacheKey(path string, version int) string {
	return fmt.Sprintf("kv:%s:v%d", path, version)
}

func (s *SecretsService) bumpCacheGen(path string) uint64 {
	v, _ := s.cacheGen.LoadOrStore(path, uint64(0))
	gen := v.(uint64) + 1
	s.cacheGen.Store(path, gen)
	return gen
}

func (s *SecretsService) cacheGenFor(path string) uint64 {
	v, ok := s.cacheGen.Load(path)
	if !ok {
		return 0
	}
	return v.(uint64)
}

func (s *SecretsService) invalidateCache(ctx context.Context, path string) {
	if s == nil || s.cache == nil {
		return
	}
	s.bumpCacheGen(path)
	s.cache.Delete(ctx, s.cacheKey(path, 0))
	if s.engine == nil {
		return
	}
	if versions, err := s.engine.ListVersions(ctx, path); err == nil {
		for _, ver := range versions {
			s.cache.Delete(ctx, s.cacheKey(path, ver.Version))
		}
	}
}

func (s *SecretsService) scopePath(ctx context.Context, path string) (string, error) {
	if s == nil || !s.tenantMode {
		return path, nil
	}
	ns := tenant.FromContext(ctx)
	if ns == "" {
		return "", common.New(common.ErrCodeValidation, "tenant namespace required")
	}
	scoped := tenant.ScopePath(ns, path, true)
	if !tenant.ValidateAccess(ns, scoped, true) {
		return "", common.New(common.ErrCodeNotFound, "secret not found")
	}
	return scoped, nil
}

// Put stores a secret version.
func (s *SecretsService) Put(ctx context.Context, path string, data map[string]any, opts secretsengine.PutOptions) (*secretsengine.PutResult, error) {
	path, err := s.scopePath(ctx, path)
	if err != nil {
		return nil, err
	}
	result, err := s.engine.Put(ctx, path, data, opts)
	if err == nil {
		s.invalidateCache(ctx, path)
	}
	audithelper.Record(s.audit, ctx, "secret.write", "secrets/kv/"+path, err, nil)
	return result, err
}

// Get reads the latest secret version.
func (s *SecretsService) Get(ctx context.Context, path string) (*secretsengine.GetResult, error) {
	return s.getVersion(ctx, path, 0)
}

// GetVersion reads a specific secret version.
func (s *SecretsService) GetVersion(ctx context.Context, path string, version int) (*secretsengine.GetResult, error) {
	return s.getVersion(ctx, path, version)
}

func (s *SecretsService) getVersion(ctx context.Context, path string, version int) (*secretsengine.GetResult, error) {
	path, err := s.scopePath(ctx, path)
	if err != nil {
		return nil, err
	}
	readGen := s.cacheGenFor(path)
	if s.cache != nil {
		if raw, ok := s.cache.Get(ctx, s.cacheKey(path, version)); ok {
			var result secretsengine.GetResult
			if json.Unmarshal(raw, &result) == nil {
				audithelper.Record(s.audit, ctx, "secret.read", "secrets/kv/"+path, nil, map[string]any{"cached": true, "version": version})
				return &result, nil
			}
		}
	}
	result, err := s.engine.GetVersion(ctx, path, version)
	if err == nil && s.cache != nil && s.cacheGenFor(path) == readGen {
		if raw, marshalErr := json.Marshal(result); marshalErr == nil {
			s.cache.Set(ctx, s.cacheKey(path, version), raw, 5*time.Minute)
		}
	}
	details := map[string]any{"version": version}
	audithelper.Record(s.audit, ctx, "secret.read", "secrets/kv/"+path, err, details)
	return result, err
}

// ListPaths returns secret paths under a prefix.
func (s *SecretsService) ListPaths(ctx context.Context, prefix string) ([]string, error) {
	prefix, err := s.scopePath(ctx, prefix)
	if err != nil {
		return nil, err
	}
	result, err := s.engine.ListPaths(ctx, prefix)
	audithelper.Record(s.audit, ctx, "secret.list", "secrets/kv/", err, map[string]any{"prefix": prefix})
	return result, err
}

// ListVersions returns version metadata for a path.
func (s *SecretsService) ListVersions(ctx context.Context, path string) ([]secretsengine.VersionMetadata, error) {
	path, err := s.scopePath(ctx, path)
	if err != nil {
		return nil, err
	}
	result, err := s.engine.ListVersions(ctx, path)
	audithelper.Record(s.audit, ctx, "secret.versions", "secrets/kv/"+path, err, nil)
	return result, err
}

// LabelsForPath returns metadata labels for the latest secret version (W44-01).
// Does not emit audit events (used by auth middleware and list filtering).
func (s *SecretsService) LabelsForPath(ctx context.Context, path string) (map[string]string, error) {
	scoped, err := s.scopePath(ctx, path)
	if err != nil {
		return nil, err
	}
	meta, err := s.engine.GetMetadata(ctx, scoped, 0)
	if err != nil {
		return nil, err
	}
	if meta == nil || len(meta.Labels) == 0 {
		return nil, nil
	}
	return meta.Labels, nil
}

// GetMetadata returns path metadata.
func (s *SecretsService) GetMetadata(ctx context.Context, path string, version int) (*secretsengine.PathMetadata, error) {
	path, err := s.scopePath(ctx, path)
	if err != nil {
		return nil, err
	}
	result, err := s.engine.GetMetadata(ctx, path, version)
	audithelper.Record(s.audit, ctx, "secret.metadata", "secrets/kv/"+path, err, nil)
	return result, err
}

// DestroyVersion marks a version destroyed.
func (s *SecretsService) DestroyVersion(ctx context.Context, path string, version int) error {
	path, err := s.scopePath(ctx, path)
	if err != nil {
		return err
	}
	err = s.engine.DestroyVersion(ctx, path, version)
	if err == nil {
		s.invalidateCache(ctx, path)
	}
	audithelper.Record(s.audit, ctx, "secret.destroy", "secrets/kv/"+path, err, map[string]any{"version": version})
	return err
}

// Delete soft-deletes a secret path.
func (s *SecretsService) Delete(ctx context.Context, path string) error {
	scoped, err := s.scopePath(ctx, path)
	if err != nil {
		return err
	}
	err = s.engine.Delete(ctx, scoped)
	if err == nil {
		s.invalidateCache(ctx, scoped)
	}
	audithelper.Record(s.audit, ctx, "secret.delete", "secrets/kv/"+scoped, err, nil)
	return err
}
