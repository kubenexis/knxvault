package middleware

import (
	"context"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/auth"
)

// AuthzAuditRecorder logs authz.denied events (W41-06).
type AuthzAuditRecorder interface {
	Record(ctx context.Context, actor, action, resource, status string, details map[string]any) error
}

// AuthzAudit records authorization denials.
type AuthzAudit struct {
	audit     AuthzAuditRecorder
	denyLimit *authDenyLimiter
}

type authDenyLimiter struct {
	mu     sync.Mutex
	last   map[string]time.Time
	minGap time.Duration
}

func newAuthDenyLimiter() *authDenyLimiter {
	return &authDenyLimiter{last: make(map[string]time.Time), minGap: 5 * time.Second}
}

func (l *authDenyLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if prev, ok := l.last[key]; ok && now.Sub(prev) < l.minGap {
		return false
	}
	l.last[key] = now
	return true
}

// NewAuthzAudit constructs an authorization denial audit helper.
func NewAuthzAudit(recorder AuthzAuditRecorder) *AuthzAudit {
	if recorder == nil {
		return nil
	}
	return &AuthzAudit{audit: recorder, denyLimit: newAuthDenyLimiter()}
}

func (a *AuthzAudit) recordDenied(c *gin.Context, principal auth.Principal, resource, capability string, err error) {
	if a == nil || a.audit == nil {
		return
	}
	key := principal.Subject + ":" + resource + ":" + capability
	if !a.denyLimit.allow(key) {
		return
	}
	details := map[string]any{
		"resource":   resource,
		"capability": capability,
		"request_id": c.GetHeader("X-Request-ID"),
		"source_ip":  c.ClientIP(),
	}
	if err != nil {
		details["reason"] = err.Error()
	}
	_ = a.audit.Record(c.Request.Context(), principal.Subject, "authz.denied", resource, "failure", details)
}
