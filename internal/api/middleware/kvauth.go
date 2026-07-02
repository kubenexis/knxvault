package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// RequireKVAccess enforces path-aware KV capabilities (W41-01, W41-05).
func RequireKVAccess(svc *auth.Service, capability string, audit *AuthzAudit) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil {
			c.Next()
			return
		}
		cap := capability
		if capability == "" {
			cap = KVCapability(c)
		}
		path := strings.TrimPrefix(c.Param("path"), "/")
		resource := "secrets/kv"
		if path != "" {
			resource = "secrets/kv/" + path
		}
		if strings.HasSuffix(path, "/metadata") {
			resource = "secrets/kv/" + strings.TrimSuffix(path, "/metadata")
		}
		if strings.HasSuffix(path, "/versions") {
			resource = "secrets/kv/" + strings.TrimSuffix(path, "/versions")
		}
		principal, ok := auth.PrincipalFromContext(c.Request.Context())
		if !ok {
			_ = c.Error(common.New(common.ErrCodeUnauthorized, "unauthenticated"))
			c.Abort()
			return
		}
		if err := svc.AuthorizePath(c.Request.Context(), principal, resource, cap); err != nil {
			if audit != nil {
				audit.recordDenied(c, principal, resource, cap, err)
			}
			_ = c.Error(err)
			c.Abort()
			return
		}
		c.Next()
	}
}
