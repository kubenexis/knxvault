// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"
)

const requestIDHeader = "X-Request-ID"

// RequestID ensures every request has a request ID.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(requestIDHeader)
		if id == "" {
			buf := make([]byte, 16)
			_, _ = rand.Read(buf)
			id = hex.EncodeToString(buf)
		}
		c.Set("request_id", id)
		c.Writer.Header().Set(requestIDHeader, id)
		c.Next()
	}
}
