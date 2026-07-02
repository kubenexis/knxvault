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
			c.Next()
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
