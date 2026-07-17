// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	kvncrypto "github.com/kubenexis/knxvault/internal/crypto"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
)

// System path for Raft-replicated AppRole definitions (encrypted envelope).
const appRoleRaftPath = "sys/internal/approles"

// AppRoleReplicator loads/saves the full AppRole map via SecretRepository (Dragonboat-backed when Raft is on).
type AppRoleReplicator struct {
	repo   repository.SecretRepository
	crypto *kvncrypto.Service
}

// AttachRaftBackend wires SecretRepository+crypto persistence onto an AppRoleStore.
// Register/Delete will write through to Raft; Authenticate still uses in-memory cache.
func (s *AppRoleStore) AttachRaftBackend(repo repository.SecretRepository, cryptoSvc *kvncrypto.Service) {
	if s == nil || repo == nil || cryptoSvc == nil {
		return
	}
	s.replicator = &AppRoleReplicator{repo: repo, crypto: cryptoSvc}
	_ = s.LoadFromRaft(context.Background())
}

// LoadFromRaft reloads AppRoles from the replicated secret blob.
func (s *AppRoleStore) LoadFromRaft(ctx context.Context) error {
	if s == nil || s.replicator == nil {
		return nil
	}
	sv, err := s.replicator.repo.GetLatest(ctx, appRoleRaftPath)
	if err != nil || sv == nil || len(sv.DataEnc) == 0 {
		return nil
	}
	plain, err := s.replicator.crypto.Open(sv.DataEnc, sv.DEKEnc)
	if err != nil {
		return err
	}
	var list []approleDiskRecord
	if err := json.Unmarshal(plain, &list); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles = make(map[string]AppRole, len(list))
	for _, r := range list {
		s.roles[r.RoleID] = AppRole{
			RoleID:     r.RoleID,
			Subject:    r.Subject,
			Policies:   append([]string(nil), r.Policies...),
			secretHash: r.SecretHash,
		}
	}
	return nil
}

func (s *AppRoleStore) persistRaftLocked(ctx context.Context) {
	if s.replicator == nil {
		return
	}
	list := make([]approleDiskRecord, 0, len(s.roles))
	for _, r := range s.roles {
		list = append(list, approleDiskRecord{
			RoleID: r.RoleID, Subject: r.Subject, Policies: append([]string(nil), r.Policies...), SecretHash: r.secretHash,
		})
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return
	}
	ct, dek, err := s.replicator.crypto.Seal(raw)
	if err != nil {
		return
	}
	sv := &domainsecrets.SecretVersion{
		ID:        uuid.New(),
		Path:      appRoleRaftPath,
		Version:   1,
		DataEnc:   ct,
		DEKEnc:    dek,
		CreatedAt: time.Now().UTC(),
	}
	// Best-effort version bump
	if latest, err := s.replicator.repo.GetLatest(ctx, appRoleRaftPath); err == nil && latest != nil {
		sv.Version = latest.Version + 1
	}
	_ = s.replicator.repo.SaveVersion(ctx, sv)
}
