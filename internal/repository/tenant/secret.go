// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package tenantrepo wraps repositories with tenant path isolation (W32-03).
package tenantrepo

import (
	"context"

	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/tenant"
)

// SecretRepository enforces tenant prefixes on KV paths.
type SecretRepository struct {
	inner   repository.SecretRepository
	tenant  string
	enabled bool
}

// WrapSecret wraps a secret repository with tenant scoping.
func WrapSecret(inner repository.SecretRepository, ns string, enabled bool) repository.SecretRepository {
	if !enabled || inner == nil {
		return inner
	}
	return &SecretRepository{inner: inner, tenant: ns, enabled: true}
}

func (r *SecretRepository) scope(path string) (string, error) {
	path = tenant.ScopePath(r.tenant, path, r.enabled)
	if !tenant.ValidateAccess(r.tenant, path, r.enabled) {
		return "", common.New(common.ErrCodeNotFound, "secret not found")
	}
	return path, nil
}

func (r *SecretRepository) SaveVersion(ctx context.Context, sv *domainsecrets.SecretVersion) error {
	p, err := r.scope(sv.Path)
	if err != nil {
		return err
	}
	sv.Path = p
	return r.inner.SaveVersion(ctx, sv)
}

func (r *SecretRepository) PutAtomic(ctx context.Context, sv *domainsecrets.SecretVersion, casVersion *int, maxVersions int) (int, error) {
	p, err := r.scope(sv.Path)
	if err != nil {
		return 0, err
	}
	sv.Path = p
	return r.inner.PutAtomic(ctx, sv, casVersion, maxVersions)
}

func (r *SecretRepository) GetLatest(ctx context.Context, path string) (*domainsecrets.SecretVersion, error) {
	p, err := r.scope(path)
	if err != nil {
		return nil, err
	}
	return r.inner.GetLatest(ctx, p)
}

func (r *SecretRepository) GetVersion(ctx context.Context, path string, version int) (*domainsecrets.SecretVersion, error) {
	p, err := r.scope(path)
	if err != nil {
		return nil, err
	}
	return r.inner.GetVersion(ctx, p, version)
}

func (r *SecretRepository) ListByPath(ctx context.Context, pathPrefix string) ([]*domainsecrets.SecretVersion, error) {
	p, err := r.scope(pathPrefix)
	if err != nil {
		return nil, err
	}
	return r.inner.ListByPath(ctx, p)
}

func (r *SecretRepository) NextVersion(ctx context.Context, path string) (int, error) {
	p, err := r.scope(path)
	if err != nil {
		return 0, err
	}
	return r.inner.NextVersion(ctx, p)
}

func (r *SecretRepository) DestroyVersion(ctx context.Context, path string, version int) error {
	p, err := r.scope(path)
	if err != nil {
		return err
	}
	return r.inner.DestroyVersion(ctx, p, version)
}

func (r *SecretRepository) UpdateDEKEnc(ctx context.Context, path string, version int, dekEnc []byte) error {
	p, err := r.scope(path)
	if err != nil {
		return err
	}
	return r.inner.UpdateDEKEnc(ctx, p, version, dekEnc)
}
