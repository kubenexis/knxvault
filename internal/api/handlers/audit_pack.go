// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/service"
)

// AuditPackHandler serves compliance audit pack export (W35-02).
type AuditPackHandler struct {
	svc *service.AuditPackService
}

// NewAuditPackHandler constructs an AuditPackHandler.
func NewAuditPackHandler(svc *service.AuditPackService) *AuditPackHandler {
	return &AuditPackHandler{svc: svc}
}

// ExportPack handles GET /sys/audit/pack.
func (h *AuditPackHandler) ExportPack(c *gin.Context) {
	var since *time.Time
	if raw := c.Query("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			_ = c.Error(err)
			return
		}
		since = &t
	}
	data, err := h.svc.Pack(c.Request.Context(), since)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", "attachment; filename=knxvault-audit-pack.zip")
	c.Data(http.StatusOK, "application/zip", data)
}
