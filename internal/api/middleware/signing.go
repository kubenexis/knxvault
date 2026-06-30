package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

const (
	headerSignature = "X-KNXVault-Signature"
	headerTimestamp = "X-KNXVault-Timestamp"
	maxSkew         = 5 * time.Minute
)

// RequestSigning verifies optional HMAC request signatures (W19).
type RequestSigning struct {
	key      []byte
	required bool
}

// NewRequestSigning constructs request signing middleware settings.
func NewRequestSigning(key string, required bool) *RequestSigning {
	if key == "" {
		return &RequestSigning{required: false}
	}
	return &RequestSigning{key: []byte(key), required: required}
}

// Middleware validates signed requests when configured.
func (s *RequestSigning) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s == nil || len(s.key) == 0 {
			c.Next()
			return
		}

		signature := c.GetHeader(headerSignature)
		timestampRaw := c.GetHeader(headerTimestamp)
		if signature == "" || timestampRaw == "" {
			if s.required {
				abortUnauthorized(c, "signed request required")
				return
			}
			c.Next()
			return
		}

		ts, err := strconv.ParseInt(timestampRaw, 10, 64)
		if err != nil {
			abortUnauthorized(c, "invalid request timestamp")
			return
		}
		reqTime := time.Unix(ts, 0)
		now := time.Now()
		if reqTime.Before(now.Add(-maxSkew)) || reqTime.After(now.Add(maxSkew)) {
			abortUnauthorized(c, "request timestamp out of range")
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			abortUnauthorized(c, "read request body")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))

		expected := computeRequestSignature(s.key, c.Request.Method, c.Request.URL.Path, timestampRaw, body)
		if !hmac.Equal([]byte(signature), []byte(expected)) {
			abortUnauthorized(c, "invalid request signature")
			return
		}
		c.Next()
	}
}

// ComputeSignature returns the HMAC signature for a request (client helper).
func ComputeSignature(key []byte, method, path, timestamp string, body []byte) string {
	return computeRequestSignature(key, method, path, timestamp, body)
}

func abortUnauthorized(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error_code": common.ErrCodeUnauthorized,
		"message":    message,
	})
}

func computeRequestSignature(key []byte, method, path, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(method))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(path))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// SignRequest adds signature headers to an HTTP request.
func SignRequest(req *http.Request, key []byte) error {
	if len(key) == 0 {
		return nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set(headerTimestamp, ts)
	req.Header.Set(headerSignature, computeRequestSignature(key, req.Method, req.URL.Path, ts, body))
	return nil
}
