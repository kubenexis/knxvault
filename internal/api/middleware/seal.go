// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// SealChecker reports operational seal status.
type SealChecker interface {
	Sealed() bool
}

// SealGuard blocks the data plane when the vault is sealed (W50-03).
// Unlike write-only sealing, authenticated secret/PKI/audit reads are also denied
// so incident seal stops exfiltration. Unseal and liveness routes are registered
// outside groups that use this middleware.
func SealGuard(checker SealChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		if checker == nil || !checker.Sealed() {
			c.Next()
			return
		}
		// Exact unseal path only (after Clean) — avoid suffix bypasses like /evil/sys/unseal.
		p := path.Clean("/" + strings.TrimSpace(c.Request.URL.Path))
		if p == "/sys/unseal" {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error_code": string(common.ErrCodeUnavailable),
			"message":    "vault is sealed",
		})
	}
}
