// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package audithelper

import (
	"context"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
)

// Actor returns the authenticated principal subject or "anonymous".
func Actor(ctx context.Context) string {
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		return principal.Subject
	}
	return "anonymous"
}

// Record writes an audit entry when the audit service is configured.
func Record(audit *auditsvc.Service, ctx context.Context, action, resource string, err error, details map[string]any) {
	if audit == nil {
		return
	}
	status := "success"
	if err != nil {
		status = "failure"
	}
	_ = audit.Record(ctx, Actor(ctx), action, resource, status, details)
}
