package middleware

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/auth"
)

// KVLabelResolver returns metadata labels for a secret path (W44-01).
type KVLabelResolver interface {
	LabelsForPath(ctx context.Context, path string) (map[string]string, error)
}

// EnrichKVResourceLabels loads KV metadata labels into the request context before path auth.
func EnrichKVResourceLabels(resolver KVLabelResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		if resolver == nil {
			c.Next()
			return
		}
		rawPath := strings.TrimPrefix(c.Param("path"), "/")
		if rawPath == "" || c.Query("list") == "true" {
			c.Next()
			return
		}
		path := strings.TrimSuffix(strings.TrimSuffix(rawPath, "/metadata"), "/versions")
		labels, err := resolver.LabelsForPath(c.Request.Context(), path)
		if err != nil || len(labels) == 0 {
			c.Next()
			return
		}
		req, ok := auth.RequestContextFromContext(c.Request.Context())
		if !ok {
			req = auth.RequestContext{}
		}
		req.ResourceLabels = labels
		c.Request = c.Request.WithContext(auth.WithRequestContext(c.Request.Context(), req))
		c.Next()
	}
}
