// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// MTLSRequired rejects requests without a verified client certificate when enabled.
func MTLSRequired(required bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !required {
			c.Next()
			return
		}
		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error_code": string(common.ErrCodeUnauthorized),
				"message":    "client certificate required",
			})
			return
		}
		c.Next()
	}
}

// MTLSForPaths applies mTLS requirement only to matching path prefixes.
func MTLSForPaths(required bool, prefixes ...string) gin.HandlerFunc {
	base := MTLSRequired(required)
	return func(c *gin.Context) {
		if !required {
			c.Next()
			return
		}
		path := c.Request.URL.Path
		for _, prefix := range prefixes {
			if prefix != "" && (path == prefix || strings.HasPrefix(path, prefix+"/")) {
				base(c)
				return
			}
		}
		c.Next()
	}
}

// ClientCertSubject returns the first peer certificate subject CN, if present.
func ClientCertSubject(c *gin.Context) string {
	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		return ""
	}
	return c.Request.TLS.PeerCertificates[0].Subject.CommonName
}

// ClientCertFingerprint returns the SHA-256 fingerprint (hex) of the leaf client cert.
func ClientCertFingerprint(c *gin.Context) string {
	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		return ""
	}
	return certFingerprint(c.Request.TLS.PeerCertificates[0])
}

func certFingerprint(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
