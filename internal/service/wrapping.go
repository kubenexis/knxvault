// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/engine/secrets/cubbyhole"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

const (
	wrapPath       = "response"
	wrapMetaPrefix = "sys/wrapping/meta/"
)

// WrappingService mints single-use wrapping tokens (M-WRAP-1 / W74-04).
// Wrap metadata is persisted (sealed) when a SecretRepository is configured so
// multi-node Raft shares single-use state.
type WrappingService struct {
	mu     sync.Mutex
	cubby  *cubbyhole.Engine
	repo   repository.SecretRepository
	crypto *crypto.Service
	audit  *auditsvc.Service
	// local cache for process-local meta when repo unavailable
	wraps  map[string]wrapMeta
	maxTTL time.Duration
}

type wrapMeta struct {
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	Creation  time.Time `json:"creation_time"`
}

// NewWrappingService constructs a wrapping service.
func NewWrappingService(cubby *cubbyhole.Engine, audit *auditsvc.Service) *WrappingService {
	return &WrappingService{
		cubby:  cubby,
		audit:  audit,
		wraps:  make(map[string]wrapMeta),
		maxTTL: time.Hour,
	}
}

// AttachStorage enables Raft/secret-repo persistence of wrap metadata.
func (s *WrappingService) AttachStorage(repo repository.SecretRepository, cryptoSvc *crypto.Service) {
	if s == nil {
		return
	}
	s.repo = repo
	s.crypto = cryptoSvc
}

// WrapResult is returned to the client instead of the secret payload.
type WrapResult struct {
	Token     string    `json:"token"`
	TTL       int       `json:"ttl_seconds"`
	Creation  time.Time `json:"creation_time"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Wrap stores payload under a one-shot wrapping token.
func (s *WrappingService) Wrap(ctx context.Context, payload map[string]any, ttl time.Duration) (*WrapResult, error) {
	if s == nil || s.cubby == nil {
		return nil, common.New(common.ErrCodeInternal, "wrapping not configured")
	}
	if len(payload) == 0 {
		return nil, common.New(common.ErrCodeValidation, "payload required")
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "token", err)
	}
	token := "knxw_" + base64.RawURLEncoding.EncodeToString(raw)
	id := hashWrap(token)
	now := time.Now().UTC()
	exp := now.Add(ttl)
	if err := s.cubby.Put(ctx, id, wrapPath, payload); err != nil {
		return nil, err
	}
	meta := wrapMeta{ExpiresAt: exp, Creation: now}
	if err := s.putMeta(ctx, id, meta); err != nil {
		_ = s.cubby.Delete(ctx, id, wrapPath)
		return nil, err
	}
	s.gcExpiredLocked(ctx)
	audithelper.Record(s.audit, ctx, "wrapping.wrap", "sys/wrapping", nil, map[string]any{"ttl": int(ttl.Seconds())})
	return &WrapResult{Token: token, TTL: int(ttl.Seconds()), Creation: now, ExpiresAt: exp}, nil
}

// Unwrap returns the payload once and invalidates the wrapping token.
func (s *WrappingService) Unwrap(ctx context.Context, token string) (map[string]any, error) {
	if s == nil || s.cubby == nil {
		return nil, common.New(common.ErrCodeInternal, "wrapping not configured")
	}
	id := hashWrap(token)
	s.mu.Lock()
	meta, err := s.getMetaLocked(ctx, id)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if meta.Used {
		s.mu.Unlock()
		return nil, common.New(common.ErrCodeForbidden, "wrapping token already used")
	}
	if time.Now().UTC().After(meta.ExpiresAt) {
		s.mu.Unlock()
		return nil, common.New(common.ErrCodeForbidden, "wrapping token expired")
	}
	meta.Used = true
	if err := s.putMetaLocked(ctx, id, meta); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Unlock()

	data, err := s.cubby.Get(ctx, id, wrapPath)
	if err != nil {
		audithelper.Record(s.audit, ctx, "wrapping.unwrap", "sys/wrapping", err, nil)
		return nil, err
	}
	_ = s.cubby.Delete(ctx, id, wrapPath)
	audithelper.Record(s.audit, ctx, "wrapping.unwrap", "sys/wrapping", nil, nil)
	return data, nil
}

// Lookup returns metadata without the payload.
func (s *WrappingService) Lookup(ctx context.Context, token string) (*WrapResult, error) {
	id := hashWrap(token)
	s.mu.Lock()
	meta, err := s.getMetaLocked(ctx, id)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if meta.Used {
		return nil, common.New(common.ErrCodeNotFound, "wrapping token not found")
	}
	if time.Now().UTC().After(meta.ExpiresAt) {
		return nil, common.New(common.ErrCodeForbidden, "wrapping token expired")
	}
	ttl := int(time.Until(meta.ExpiresAt).Seconds())
	if ttl < 0 {
		ttl = 0
	}
	return &WrapResult{TTL: ttl, Creation: meta.Creation, ExpiresAt: meta.ExpiresAt}, nil
}

func (s *WrappingService) putMeta(ctx context.Context, id string, meta wrapMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putMetaLocked(ctx, id, meta)
}

func (s *WrappingService) putMetaLocked(ctx context.Context, id string, meta wrapMeta) error {
	s.wraps[id] = meta
	if s.repo == nil || s.crypto == nil {
		return nil
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	dataEnc, dekEnc, err := s.crypto.Seal(raw)
	if err != nil {
		return err
	}
	sv := &domainsecrets.SecretVersion{
		ID:        uuid.New(),
		Path:      wrapMetaPrefix + id,
		DataEnc:   dataEnc,
		DEKEnc:    dekEnc,
		CreatedAt: time.Now().UTC(),
		Labels:    map[string]string{"engine": "wrapping"},
	}
	_, err = s.repo.PutAtomic(ctx, sv, nil, 1)
	return err
}

func (s *WrappingService) getMetaLocked(ctx context.Context, id string) (wrapMeta, error) {
	if meta, ok := s.wraps[id]; ok {
		return meta, nil
	}
	if s.repo == nil || s.crypto == nil {
		return wrapMeta{}, common.New(common.ErrCodeNotFound, "wrapping token not found")
	}
	sv, err := s.repo.GetLatest(ctx, wrapMetaPrefix+id)
	if err != nil {
		return wrapMeta{}, common.New(common.ErrCodeNotFound, "wrapping token not found")
	}
	plain, err := s.crypto.Open(sv.DataEnc, sv.DEKEnc)
	if err != nil {
		return wrapMeta{}, err
	}
	var meta wrapMeta
	if err := json.Unmarshal(plain, &meta); err != nil {
		return wrapMeta{}, err
	}
	s.wraps[id] = meta
	return meta, nil
}

func (s *WrappingService) gcExpiredLocked(ctx context.Context) {
	now := time.Now().UTC()
	for id, meta := range s.wraps {
		if meta.Used || now.After(meta.ExpiresAt) {
			delete(s.wraps, id)
			if s.repo != nil {
				if sv, err := s.repo.GetLatest(ctx, wrapMetaPrefix+id); err == nil {
					_ = s.repo.DestroyVersion(ctx, sv.Path, sv.Version)
				}
			}
			_ = s.cubby.Delete(ctx, id, wrapPath)
		}
	}
}

// WrapJSON is a helper for arbitrary JSON-serializable payload.
func WrapJSON(payload any) (map[string]any, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{"data": string(b)}, nil
	}
	return m, nil
}

func hashWrap(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
