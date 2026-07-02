package auth

import "context"

// LoginLockoutKey returns a stable per-IP lockout key for unauthenticated login attempts.
func LoginLockoutKey(method string, auditCtx LoginAuditContext) string {
	if auditCtx.SourceIP != "" {
		return LockoutKey(method, auditCtx.SourceIP)
	}
	return LockoutKey(method, "unknown")
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
