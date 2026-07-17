// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// RequirePathCapability enforces path-aware RBAC (W41-01).
func RequirePathCapability(svc *auth.Service, baseResource, capability string, pathParam string, audit *AuthzAudit) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil {
			// Fail closed (aligned with W50-11 Auth/RequirePermission).
			_ = c.Error(common.New(common.ErrCodeUnavailable, "auth service not configured"))
			c.Abort()
			return
		}
		path := strings.TrimPrefix(c.Param(pathParam), "/")
		resource := baseResource
		if path != "" {
			resource = baseResource + "/" + path
		}
		principal, ok := auth.PrincipalFromContext(c.Request.Context())
		if !ok {
			_ = c.Error(common.New(common.ErrCodeUnauthorized, "unauthenticated"))
			c.Abort()
			return
		}
		if err := svc.AuthorizePath(c.Request.Context(), principal, resource, capability); err != nil {
			if audit != nil {
				audit.recordDenied(c, principal, resource, capability, err)
			}
			_ = c.Error(err)
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequirePKISignCapability enforces path-scoped PKI sign capability (W50-29 / W52-04).
// Checks resource "{mount}/sign/{role}" first, then mount-level "{mount}/sign".
// Coarse "pki" write alone is NOT sufficient (removed compatibility fallback).
// Policies that need broad sign should grant "pki/sign/*" or "pki/*" path patterns.
func RequirePKISignCapability(svc *auth.Service, defaultMount string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil {
			_ = c.Error(common.New(common.ErrCodeUnavailable, "auth service not configured"))
			c.Abort()
			return
		}
		principal, ok := auth.PrincipalFromContext(c.Request.Context())
		if !ok {
			_ = c.Error(common.New(common.ErrCodeUnauthorized, "unauthenticated"))
			c.Abort()
			return
		}
		mount := strings.TrimSpace(c.Param("mount"))
		if mount == "" {
			mount = defaultMount
		}
		if mount == "" {
			mount = "pki"
		}
		role := strings.TrimSpace(c.Param("role"))
		candidates := []string{mount + "/sign"}
		if role != "" {
			candidates = []string{mount + "/sign/" + role, mount + "/sign/*", mount + "/sign", "pki/sign/" + role, "pki/sign/*"}
		}
		var lastErr error
		for _, pathResource := range candidates {
			if err := svc.AuthorizePath(c.Request.Context(), principal, pathResource, auth.CapWrite); err == nil {
				c.Next()
				return
			} else {
				lastErr = err
			}
		}
		// Also allow admin-style glob policies that grant pki/* via path auth on "pki/sign/..."
		if err := svc.AuthorizePath(c.Request.Context(), principal, "pki/*", auth.CapWrite); err == nil {
			c.Next()
			return
		}
		if lastErr == nil {
			lastErr = common.New(common.ErrCodeForbidden, "access denied")
		}
		_ = c.Error(lastErr)
		c.Abort()
	}
}

// KVCapability picks read vs list for KV endpoints (W41-05).
func KVCapability(c *gin.Context) string {
	rawPath := strings.TrimPrefix(c.Param("path"), "/")
	if c.Query("list") == "true" {
		return auth.CapList
	}
	if strings.HasSuffix(rawPath, "/metadata") || strings.HasSuffix(rawPath, "/versions") {
		return auth.CapList
	}
	return auth.CapRead
}
