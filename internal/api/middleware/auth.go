package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// Auth authenticates requests using bearer tokens.
func Auth(svc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil {
			c.Next()
			return
		}

		token := extractToken(c)
		if token == "" {
			_ = c.Error(common.New(common.ErrCodeUnauthorized, "missing authentication token"))
			c.Abort()
			return
		}

		record, err := svc.LoginWithToken(c.Request.Context(), token)
		if err != nil {
			_ = c.Error(err)
			c.Abort()
			return
		}

		ctx := auth.WithPrincipal(c.Request.Context(), auth.Principal{
			Subject:  record.Subject,
			Policies: record.Policies,
			TokenID:  record.ID,
		})
		ctx = auth.WithRequestContext(ctx, auth.RequestContext{
			ClientIP:  c.ClientIP(),
			Namespace: strings.TrimSpace(c.GetHeader("X-KNX-Namespace")),
		})
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// RequirePermission enforces RBAC for a resource/action pair.
func RequirePermission(svc *auth.Service, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil {
			c.Next()
			return
		}

		principal, ok := auth.PrincipalFromContext(c.Request.Context())
		if !ok {
			_ = c.Error(common.New(common.ErrCodeUnauthorized, "unauthenticated"))
			c.Abort()
			return
		}
		if err := svc.Authorize(c.Request.Context(), principal, resource, action); err != nil {
			_ = c.Error(err)
			c.Abort()
			return
		}
		c.Next()
	}
}

func extractToken(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}
	if token := c.GetHeader("X-KNXVault-Token"); token != "" {
		return token
	}
	return ""
}
