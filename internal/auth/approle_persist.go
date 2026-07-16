package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// file-backed AppRole persistence (W50-04). Not Raft-replicated but survives process restart.

type approleDiskRecord struct {
	RoleID     string   `json:"role_id"`
	Subject    string   `json:"subject"`
	Policies   []string `json:"policies"`
	SecretHash string   `json:"secret_hash"`
}

// SetPersistPath enables load/save of AppRole definitions to path.
func (s *AppRoleStore) SetPersistPath(path string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistPath = path
	s.loadLocked()
}

func (s *AppRoleStore) loadLocked() {
	if s.persistPath == "" {
		return
	}
	raw, err := os.ReadFile(s.persistPath)
	if err != nil || len(raw) == 0 {
		return
	}
	var list []approleDiskRecord
	if err := json.Unmarshal(raw, &list); err != nil {
		return
	}
	if s.roles == nil {
		s.roles = make(map[string]AppRole)
	}
	for _, r := range list {
		s.roles[r.RoleID] = AppRole{
			RoleID: r.RoleID, Subject: r.Subject,
			Policies: append([]string(nil), r.Policies...),
			secretHash: r.SecretHash,
		}
	}
}

func (s *AppRoleStore) saveLocked() {
	if s.persistPath == "" {
		return
	}
	list := make([]approleDiskRecord, 0, len(s.roles))
	for _, r := range s.roles {
		list = append(list, approleDiskRecord{
			RoleID: r.RoleID, Subject: r.Subject,
			Policies: append([]string(nil), r.Policies...),
			SecretHash: r.secretHash,
		})
	}
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.persistPath), 0o700)
	_ = os.WriteFile(s.persistPath, raw, 0o600)
}
