// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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

// LeaseIDSeparator separates tenant namespace from lease ID (path-safe; avoids Gin :lease_id slash issues).
const LeaseIDSeparator = "."

// ScopeLeaseID prefixes lease IDs with tenant (W64-01).
// Uses "tenant.leaseid" (not slash) so path params and wildcards work.
func ScopeLeaseID(tenant, leaseID string, enabled bool) string {
	leaseID = strings.TrimSpace(leaseID)
	if !enabled || tenant == "" || leaseID == "" {
		return leaseID
	}
	// Accept legacy slash-prefix for in-flight IDs; normalize to dot form when re-scoping bare IDs.
	if strings.HasPrefix(leaseID, tenant+LeaseIDSeparator) || strings.HasPrefix(leaseID, tenant+"/") {
		return leaseID
	}
	return tenant + LeaseIDSeparator + leaseID
}

// ValidateLeaseIDAccess rejects cross-tenant lease ID use.
func ValidateLeaseIDAccess(tenant, leaseID string, enabled bool) bool {
	if !enabled || tenant == "" {
		return true
	}
	leaseID = strings.TrimSpace(leaseID)
	return strings.HasPrefix(leaseID, tenant+LeaseIDSeparator) || strings.HasPrefix(leaseID, tenant+"/")
}
