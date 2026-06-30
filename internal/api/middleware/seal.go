package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// SealChecker reports operational seal status.
type SealChecker interface {
	Sealed() bool
}

// SealGuard blocks mutating requests when the vault is sealed.
func SealGuard(checker SealChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		if checker == nil || !checker.Sealed() {
			c.Next()
			return
		}
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		default:
		}
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error_code": string(common.ErrCodeUnavailable),
			"message":    "vault is sealed",
		})
	}
}
