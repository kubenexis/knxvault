// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"strings"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

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

// NamespaceHeader is the optional caller namespace for RBAC condition evaluation.
const NamespaceHeader = "X-KNX-Namespace"

// ClusterHeader is the optional cluster identifier for ABAC conditions (W44-02).
const ClusterHeader = "X-KNX-Cluster"

// RequestNamespace resolves the namespace for policy conditions from the header or K8s SA subject.
func RequestNamespace(header, subject string) string {
	ns, _ := ResolveTenantNamespace(header, subject)
	return ns
}

// ResolveTenantNamespace derives tenant namespace and rejects SA header spoofing.
func ResolveTenantNamespace(header, subject string) (string, error) {
	header = strings.TrimSpace(header)
	if id, ok := ParseServiceAccountUsername(subject); ok {
		if header != "" && header != id.Namespace {
			return "", common.New(common.ErrCodeForbidden, "namespace header does not match service account")
		}
		return id.Namespace, nil
	}
	if header != "" {
		return header, nil
	}
	return "", nil
}
