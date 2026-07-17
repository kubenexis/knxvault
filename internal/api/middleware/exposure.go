// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

const (
	exposureSignatureHeader = "X-KNXVault-Exposure-Signature"
	exposureTimestampHeader = "X-KNXVault-Exposure-Timestamp"
	// MaxExposureSkew is the max absolute clock skew accepted for signed exposure reports (W50-24).
	MaxExposureSkew = 5 * time.Minute
)

// ExposureSigning verifies HMAC signatures on exposure reports.
type ExposureSigning struct {
	key     []byte
	seenMu  sync.Mutex
	seen    map[string]time.Time
	seenTTL time.Duration
	// maxSkew is absolute |now-ts| allowed; 0 uses MaxExposureSkew.
	maxSkew time.Duration
}

// NewExposureSigning constructs exposure report signing middleware.
func NewExposureSigning(key string) *ExposureSigning {
	if key == "" {
		return nil
	}
	return &ExposureSigning{
		key:     []byte(key),
		seen:    make(map[string]time.Time),
		seenTTL: 5 * time.Minute,
		maxSkew: MaxExposureSkew,
	}
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

// SignExposurePayload computes the HMAC for body + timestamp (tests / clients).
// MAC = HMAC-SHA256(key, timestamp + "\n" + body).
func SignExposurePayload(key, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
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
		tsHeader := c.GetHeader(exposureTimestampHeader)
		if tsHeader == "" {
			abortUnauthorized(c, "exposure timestamp required")
			return
		}
		tsUnix, err := strconv.ParseInt(tsHeader, 10, 64)
		if err != nil {
			abortUnauthorized(c, "invalid exposure timestamp")
			return
		}
		skew := s.maxSkew
		if skew <= 0 {
			skew = MaxExposureSkew
		}
		ts := time.Unix(tsUnix, 0)
		if d := time.Since(ts); d > skew || d < -skew {
			abortUnauthorized(c, "exposure timestamp outside allowed skew")
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			abortUnauthorized(c, "read body failed")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		expected := SignExposurePayload(string(s.key), tsHeader, body)
		if !hmac.Equal([]byte(signature), []byte(expected)) {
			abortUnauthorized(c, "invalid exposure signature")
			return
		}
		// Replay key includes timestamp so same body at different times is distinct.
		replayKey := tsHeader + ":" + signature
		if !s.markSeen(replayKey) {
			abortUnauthorized(c, "exposure report replay detected")
			return
		}
		c.Next()
	}
}
