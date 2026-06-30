package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

const exposureSignatureHeader = "X-KNXVault-Exposure-Signature"

// ExposureSigning verifies HMAC signatures on exposure reports.
type ExposureSigning struct {
	key []byte
}

// NewExposureSigning constructs exposure report signing middleware.
func NewExposureSigning(key string) *ExposureSigning {
	if key == "" {
		return nil
	}
	return &ExposureSigning{key: []byte(key)}
}

// Middleware validates the exposure report signature when configured.
func (s *ExposureSigning) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s == nil || len(s.key) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error_code": string(common.ErrCodeUnauthorized),
				"message":    "exposure signing not configured",
			})
			return
		}
		signature := c.GetHeader(exposureSignatureHeader)
		if signature == "" {
			abortUnauthorized(c, "exposure signature required")
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			abortUnauthorized(c, "read body failed")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		mac := hmac.New(sha256.New, s.key)
		_, _ = mac.Write(body)
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(signature), []byte(expected)) {
			abortUnauthorized(c, "invalid exposure signature")
			return
		}
		c.Next()
	}
}
