package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

const exposureSignatureHeader = "X-KNXVault-Exposure-Signature"

// ExposureSigning verifies HMAC signatures on exposure reports.
type ExposureSigning struct {
	key      []byte
	seenMu   sync.Mutex
	seen     map[string]time.Time
	seenTTL  time.Duration
}

// NewExposureSigning constructs exposure report signing middleware.
func NewExposureSigning(key string) *ExposureSigning {
	if key == "" {
		return nil
	}
	return &ExposureSigning{key: []byte(key), seen: make(map[string]time.Time), seenTTL: 5 * time.Minute}
}

func (s *ExposureSigning) markSeen(signature string) bool {
	now := time.Now()
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	for sig, at := range s.seen {
		if now.Sub(at) > s.seenTTL {
			delete(s.seen, sig)
		}
	}
	if _, ok := s.seen[signature]; ok {
		return false
	}
	s.seen[signature] = now
	return true
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
		if !s.markSeen(signature) {
			abortUnauthorized(c, "exposure report replay detected")
			return
		}
		c.Next()
	}
}
