package middleware

import (
	"crypto/x509"
	"net/http"

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
			if len(prefix) > 0 && (path == prefix || len(path) > len(prefix) && path[:len(prefix)] == prefix) {
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

// ClientCertFingerprint returns the SHA-256 fingerprint of the leaf client cert.
func ClientCertFingerprint(c *gin.Context) string {
	if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
		return ""
	}
	return certFingerprint(c.Request.TLS.PeerCertificates[0])
}

func certFingerprint(cert *x509.Certificate) string {
	sum := cert.Signature
	if len(sum) == 0 {
		return ""
	}
	// Use raw cert bytes for stable identity.
	raw := cert.Raw
	if len(raw) == 0 {
		return ""
	}
	h := append([]byte(nil), raw[:mtlsMin(8, len(raw))]...)
	return string(h)
}

func mtlsMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
