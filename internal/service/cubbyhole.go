// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/engine/secrets/cubbyhole"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// CubbyholeService exposes token-scoped private KV (M-WRAP-1).
type CubbyholeService struct {
	engine *cubbyhole.Engine
	audit  *auditsvc.Service
}

// NewCubbyholeService constructs the service.
func NewCubbyholeService(engine *cubbyhole.Engine, audit *auditsvc.Service) *CubbyholeService {
	return &CubbyholeService{engine: engine, audit: audit}
}

// Put stores a secret for the token.
func (s *CubbyholeService) Put(ctx context.Context, tokenID, path string, data map[string]any) error {
	if s == nil || s.engine == nil {
		return common.New(common.ErrCodeInternal, "cubbyhole not configured")
	}
	err := s.engine.Put(ctx, tokenID, path, data)
	audithelper.Record(s.audit, ctx, "cubbyhole.put", "cubbyhole/"+path, err, nil)
	return err
}

// Get reads a secret for the token.
func (s *CubbyholeService) Get(ctx context.Context, tokenID, path string) (map[string]any, error) {
	if s == nil || s.engine == nil {
		return nil, common.New(common.ErrCodeInternal, "cubbyhole not configured")
	}
	data, err := s.engine.Get(ctx, tokenID, path)
	audithelper.Record(s.audit, ctx, "cubbyhole.get", "cubbyhole/"+path, err, nil)
	return data, err
}

// Delete removes a path for the token.
func (s *CubbyholeService) Delete(ctx context.Context, tokenID, path string) error {
	if s == nil || s.engine == nil {
		return common.New(common.ErrCodeInternal, "cubbyhole not configured")
	}
	err := s.engine.Delete(ctx, tokenID, path)
	audithelper.Record(s.audit, ctx, "cubbyhole.delete", "cubbyhole/"+path, err, nil)
	return err
}

// WipeToken clears all cubbyhole data for a token.
func (s *CubbyholeService) WipeToken(ctx context.Context, tokenID string) error {
	if s == nil || s.engine == nil {
		return nil
	}
	return s.engine.WipeToken(ctx, tokenID)
}
