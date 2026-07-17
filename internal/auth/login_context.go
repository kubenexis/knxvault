// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth

import "context"

// LoginLockoutKey returns a lockout identity key. Prefers client identity when known
// (W50-18) so lockouts are not solely IP-based behind shared NATs; falls back to source IP.
func LoginLockoutKey(method string, auditCtx LoginAuditContext) string {
	if auditCtx.ClientIdentity != "" {
		return LockoutKey(method, auditCtx.ClientIdentity)
	}
	if auditCtx.SourceIP != "" {
		return LockoutKey(method, auditCtx.SourceIP)
	}
	return LockoutKey(method, "unknown")
}

// LoginLockoutKeys returns all keys that should be checked for lockout status
// (identity and IP) so early IP lockouts still apply after identity is known.
func LoginLockoutKeys(method string, auditCtx LoginAuditContext) []string {
	seen := map[string]struct{}{}
	var keys []string
	add := func(k string) {
		if k == "" {
			return
		}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	if auditCtx.ClientIdentity != "" {
		add(LockoutKey(method, auditCtx.ClientIdentity))
	}
	if auditCtx.SourceIP != "" {
		add(LockoutKey(method, auditCtx.SourceIP))
	}
	if len(keys) == 0 {
		add(LockoutKey(method, "unknown"))
	}
	return keys
}

func loginAuditFromContext(ctx context.Context, method string) LoginAuditContext {
	auditCtx := LoginAuditContext{AuthMethod: method}
	if req, ok := RequestContextFromContext(ctx); ok {
		auditCtx.SourceIP = req.ClientIP
		auditCtx.Namespace = req.Namespace
		auditCtx.RequestID = req.RequestID
	}
	return auditCtx
}

// WithLoginAuditContext attaches login audit metadata from HTTP handlers.
func WithLoginAuditContext(ctx context.Context, sourceIP, requestID string) context.Context {
	req, ok := RequestContextFromContext(ctx)
	if !ok {
		req = RequestContext{}
	}
	req.ClientIP = sourceIP
	req.RequestID = requestID
	ctx = WithRequestContext(ctx, req)
	return ctx
}
