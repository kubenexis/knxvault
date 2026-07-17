// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/base64"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/engine/transit"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// TransitService wraps the transit engine with audit (M-TRANSIT-1).
type TransitService struct {
	engine *transit.Engine
	audit  *auditsvc.Service
}

// NewTransitService constructs a transit service.
func NewTransitService(engine *transit.Engine, audit *auditsvc.Service) *TransitService {
	return &TransitService{engine: engine, audit: audit}
}

// CreateKey creates a transit key.
func (s *TransitService) CreateKey(ctx context.Context, name string) (*transit.KeyMeta, error) {
	if s == nil || s.engine == nil {
		return nil, common.New(common.ErrCodeInternal, "transit not configured")
	}
	meta, err := s.engine.CreateKey(ctx, name)
	audithelper.Record(s.audit, ctx, "transit.key.create", "transit/keys/"+name, err, nil)
	return meta, err
}

// ReadKey returns key metadata.
func (s *TransitService) ReadKey(ctx context.Context, name string) (*transit.KeyMeta, error) {
	if s == nil || s.engine == nil {
		return nil, common.New(common.ErrCodeInternal, "transit not configured")
	}
	return s.engine.ReadKey(ctx, name)
}

// RotateKey rotates a key.
func (s *TransitService) RotateKey(ctx context.Context, name string) (*transit.KeyMeta, error) {
	if s == nil || s.engine == nil {
		return nil, common.New(common.ErrCodeInternal, "transit not configured")
	}
	meta, err := s.engine.RotateKey(ctx, name)
	audithelper.Record(s.audit, ctx, "transit.key.rotate", "transit/keys/"+name, err, nil)
	return meta, err
}

// Encrypt encrypts base64 or raw plaintext string; returns ciphertext.
func (s *TransitService) Encrypt(ctx context.Context, name, plaintext string, keyVersion int) (string, error) {
	if s == nil || s.engine == nil {
		return "", common.New(common.ErrCodeInternal, "transit not configured")
	}
	pt := []byte(plaintext)
	if b, err := base64.StdEncoding.DecodeString(plaintext); err == nil && len(b) > 0 {
		// Prefer raw string; only use base64 if caller used standard encoding intentionally is ambiguous.
		// Keep plaintext as UTF-8 bytes for API simplicity.
		_ = b
	}
	ct, err := s.engine.Encrypt(ctx, name, pt, keyVersion)
	audithelper.Record(s.audit, ctx, "transit.encrypt", "transit/encrypt/"+name, err, nil)
	return ct, err
}

// Decrypt decrypts ciphertext to string.
func (s *TransitService) Decrypt(ctx context.Context, name, ciphertext string) (string, error) {
	if s == nil || s.engine == nil {
		return "", common.New(common.ErrCodeInternal, "transit not configured")
	}
	pt, err := s.engine.Decrypt(ctx, name, ciphertext)
	audithelper.Record(s.audit, ctx, "transit.decrypt", "transit/decrypt/"+name, err, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Rewrap rewraps ciphertext to latest key version.
func (s *TransitService) Rewrap(ctx context.Context, name, ciphertext string) (string, error) {
	if s == nil || s.engine == nil {
		return "", common.New(common.ErrCodeInternal, "transit not configured")
	}
	return s.engine.Rewrap(ctx, name, ciphertext)
}

// Sign signs input.
func (s *TransitService) Sign(ctx context.Context, name, input string, keyVersion int) (string, error) {
	if s == nil || s.engine == nil {
		return "", common.New(common.ErrCodeInternal, "transit not configured")
	}
	return s.engine.Sign(ctx, name, []byte(input), keyVersion)
}

// Verify verifies signature.
func (s *TransitService) Verify(ctx context.Context, name, input, signature string) (bool, error) {
	if s == nil || s.engine == nil {
		return false, common.New(common.ErrCodeInternal, "transit not configured")
	}
	return s.engine.Verify(ctx, name, []byte(input), signature)
}

// HMAC computes HMAC.
func (s *TransitService) HMAC(ctx context.Context, name, input string, keyVersion int) (string, error) {
	if s == nil || s.engine == nil {
		return "", common.New(common.ErrCodeInternal, "transit not configured")
	}
	return s.engine.HMAC(ctx, name, []byte(input), keyVersion)
}
