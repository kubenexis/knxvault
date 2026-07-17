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

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/engine/secrets/cubbyhole"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

const wrapPath = "response"

// WrappingService mints single-use wrapping tokens (M-WRAP-1).
type WrappingService struct {
	mu     sync.Mutex
	cubby  *cubbyhole.Engine
	audit  *auditsvc.Service
	wraps  map[string]wrapMeta // hash(token) -> meta
	maxTTL time.Duration
}

type wrapMeta struct {
	ExpiresAt time.Time
	Used      bool
	Creation  time.Time
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
	s.mu.Lock()
	s.wraps[id] = wrapMeta{ExpiresAt: exp, Creation: now}
	s.mu.Unlock()
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
	meta, ok := s.wraps[id]
	if !ok {
		s.mu.Unlock()
		return nil, common.New(common.ErrCodeNotFound, "wrapping token not found")
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
	s.wraps[id] = meta
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
	meta, ok := s.wraps[id]
	s.mu.Unlock()
	if !ok || meta.Used {
		return nil, common.New(common.ErrCodeNotFound, "wrapping token not found")
	}
	if time.Now().UTC().After(meta.ExpiresAt) {
		return nil, common.New(common.ErrCodeForbidden, "wrapping token expired")
	}
	ttl := int(time.Until(meta.ExpiresAt).Seconds())
	if ttl < 0 {
		ttl = 0
	}
	_ = ctx
	return &WrapResult{TTL: ttl, Creation: meta.Creation, ExpiresAt: meta.ExpiresAt}, nil
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
