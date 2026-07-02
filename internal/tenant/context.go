// Package tenant provides multi-tenancy context propagation (W32-01–05).
package tenant

import (
	"context"
	"strings"
)

type tenantKey struct{}

// FromContext returns the tenant namespace from context.
func FromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(tenantKey{}).(string)
	return v
}

// WithContext stores tenant namespace on context.
func WithContext(ctx context.Context, namespace string) context.Context {
	return context.WithValue(ctx, tenantKey{}, strings.TrimSpace(namespace))
}

// ScopePath prefixes secret paths with tenant when tenant mode is enabled.
func ScopePath(tenant, path string, enabled bool) string {
	path = strings.TrimPrefix(path, "/")
	if !enabled || tenant == "" {
		return path
	}
	if strings.HasPrefix(path, tenant+"/") {
		return path
	}
	return tenant + "/" + path
}

// ValidateAccess rejects cross-tenant path access at repository boundary.
func ValidateAccess(tenant, path string, enabled bool) bool {
	if !enabled || tenant == "" {
		return true
	}
	path = strings.TrimPrefix(path, "/")
	return strings.HasPrefix(path, tenant+"/") || path == tenant
}
