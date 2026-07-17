// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/repository"
)

// MasterKeyService rotates master keys and re-encrypts stored DEKs.
type MasterKeyService struct {
	crypto  *crypto.Service
	cas     repository.CARepository
	secrets repository.SecretRepository
	// multiNodeRaft when true requires allowInsecure for in-process rotation (W76/W63).
	multiNodeRaft bool
	allowInsecure bool
}

// NewMasterKeyService constructs a master key rotation service.
func NewMasterKeyService(cryptoSvc *crypto.Service, cas repository.CARepository, secrets repository.SecretRepository) *MasterKeyService {
	return &MasterKeyService{crypto: cryptoSvc, cas: cas, secrets: secrets}
}

// SetRaftRotationPolicy configures multi-node Raft rotation guards.
func (s *MasterKeyService) SetRaftRotationPolicy(multiNode bool, allowInsecure bool) {
	if s != nil {
		s.multiNodeRaft = multiNode
		s.allowInsecure = allowInsecure
	}
}

// RotateRequest carries a new master key.
type RotateRequest struct {
	NewKeyBase64 string
}

// RotateResult summarizes a rotation operation.
type RotateResult struct {
	KeyVersion byte `json:"key_version"`
}

// Rotate accepts a new master key and makes it active for new encryptions.
func (s *MasterKeyService) Rotate(_ context.Context, req RotateRequest) (*RotateResult, error) {
	if s == nil || s.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "master key service not configured")
	}
	if s.multiNodeRaft && !s.allowInsecure {
		return nil, common.New(common.ErrCodeForbidden,
			"master key rotation on multi-node Raft requires KNXVAULT_MASTER_KEY_ROTATION_ALLOW_INSECURE=true and distributing previous keys via KNXVAULT_MASTER_KEY_PREVIOUS on every node")
	}
	raw, err := base64.StdEncoding.DecodeString(req.NewKeyBase64)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "invalid base64 master key", err)
	}
	if len(raw) != 32 {
		return nil, common.New(common.ErrCodeValidation, fmt.Sprintf("master key must be 32 bytes, got %d", len(raw)))
	}
	version, err := s.crypto.RotateMasterKey(raw)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "rotate master key", err)
	}
	return &RotateResult{KeyVersion: version}, nil
}

// ReencryptResult counts re-encrypted entities.
type ReencryptResult struct {
	CAs     int `json:"cas"`
	Secrets int `json:"secrets"`
}

// ReencryptDEKs re-wraps DEKs that use older master key versions.
func (s *MasterKeyService) ReencryptDEKs(ctx context.Context, limit int) (*ReencryptResult, error) {
	if s == nil || s.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "master key service not configured")
	}
	if limit <= 0 {
		limit = 100
	}
	result := &ReencryptResult{}

	if s.cas != nil {
		cas, err := s.cas.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, ca := range cas {
			if result.CAs+result.Secrets >= limit {
				break
			}
			if !s.crypto.DEKNeedsReencrypt(ca.DEKEnc) {
				continue
			}
			newEnc, err := s.crypto.ReencryptDEK(ca.DEKEnc)
			if err != nil {
				return nil, common.Wrap(common.ErrCodeInternal, "reencrypt ca dek", err)
			}
			ca.DEKEnc = newEnc
			if err := s.cas.Save(ctx, ca); err != nil {
				return nil, err
			}
			result.CAs++
		}
	}

	if s.secrets != nil {
		versions, err := s.secrets.ListByPath(ctx, "")
		if err != nil {
			return nil, err
		}
		for _, sv := range versions {
			if result.CAs+result.Secrets >= limit {
				break
			}
			if !s.crypto.DEKNeedsReencrypt(sv.DEKEnc) {
				continue
			}
			newEnc, err := s.crypto.ReencryptDEK(sv.DEKEnc)
			if err != nil {
				return nil, common.Wrap(common.ErrCodeInternal, "reencrypt secret dek", err)
			}
			if err := s.secrets.UpdateDEKEnc(ctx, sv.Path, sv.Version, newEnc); err != nil {
				return nil, err
			}
			result.Secrets++
		}
	}

	return result, nil
}
