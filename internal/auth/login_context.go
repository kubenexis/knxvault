package auth

import "context"

func loginAuditFromContext(ctx context.Context, method string) LoginAuditContext {
	auditCtx := LoginAuditContext{AuthMethod: method}
	if req, ok := RequestContextFromContext(ctx); ok {
		auditCtx.SourceIP = req.ClientIP
		auditCtx.Namespace = req.Namespace
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
	ctx = WithRequestContext(ctx, req)
	return ctx
}
