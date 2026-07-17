// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"strings"

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
		var ns string
		if principal, ok := auth.PrincipalFromContext(c.Request.Context()); ok {
			resolved, err := auth.ResolveTenantNamespace(c.GetHeader(auth.NamespaceHeader), principal.Subject)
			if err != nil {
				_ = c.Error(err)
				c.Abort()
				return
			}
			ns = resolved
		} else {
			ns = strings.TrimSpace(c.GetHeader(auth.NamespaceHeader))
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
