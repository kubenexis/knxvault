// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
)

type stubLabelResolver struct {
	labels map[string]string
}

func (s stubLabelResolver) LabelsForPath(_ context.Context, path string) (map[string]string, error) {
	if path == "app/x" {
		return s.labels, nil
	}
	return nil, nil
}

func TestEnrichKVResourceLabelsSetsContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resolver := stubLabelResolver{labels: map[string]string{"owner": "team-a"}}

	r := gin.New()
	r.GET("/secrets/kv/*path", func(c *gin.Context) {
		c.Next()
	}, middleware.EnrichKVResourceLabels(resolver), func(c *gin.Context) {
		req, ok := auth.RequestContextFromContext(c.Request.Context())
		if !ok || req.ResourceLabels["owner"] != "team-a" {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/secrets/kv/app/x", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}
