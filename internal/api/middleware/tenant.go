package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/tenant"
)

// TenantEnforcement requires namespace on mutating routes when tenant mode is enabled (W32-02).
func TenantEnforcement(enabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !enabled {
			c.Next()
			return
		}
		ns := c.GetHeader(auth.NamespaceHeader)
		if ns == "" {
			if principal, ok := auth.PrincipalFromContext(c.Request.Context()); ok {
				ns = auth.RequestNamespace("", principal.Subject)
			}
		}
		if ns == "" {
			_ = c.Error(common.New(common.ErrCodeValidation, "X-KNX-Namespace is required in tenant mode"))
			c.Abort()
			return
		}
		ctx := tenant.WithContext(c.Request.Context(), ns)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
