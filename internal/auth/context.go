package auth

import "context"

type contextKey string

const (
	principalKey      contextKey = "knxvault-principal"
	requestContextKey contextKey = "knxvault-request-context"
)

// Principal holds authenticated caller metadata.
type Principal struct {
	Subject          string
	Policies         []string
	TokenID          string
	ParentIdentityID string
	AgentID          string
	AllowedActions   []string
	PathPrefix       string
}

// WithPrincipal stores principal on context.
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey, principal)
}

// PrincipalFromContext returns the authenticated principal.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey).(Principal)
	return principal, ok
}

// WithRequestContext stores request metadata for policy conditions.
func WithRequestContext(ctx context.Context, req RequestContext) context.Context {
	return context.WithValue(ctx, requestContextKey, req)
}

// RequestContextFromContext returns request metadata when present.
func RequestContextFromContext(ctx context.Context) (RequestContext, bool) {
	req, ok := ctx.Value(requestContextKey).(RequestContext)
	return req, ok
}
