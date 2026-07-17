// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/service"
)

// LeaseHandler serves unified lease endpoints (M-LEASE-1 / W67).
type LeaseHandler struct {
	svc *service.LeaseService
}

// NewLeaseHandler constructs a LeaseHandler.
func NewLeaseHandler(svc *service.LeaseService) *LeaseHandler {
	return &LeaseHandler{svc: svc}
}

// Get handles GET /sys/leases/:lease_id.
func (h *LeaseHandler) Get(c *gin.Context) {
	view, err := h.svc.Get(c.Request.Context(), c.Param("lease_id"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, leaseJSON(view))
}

// List handles GET /sys/leases.
func (h *LeaseHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	views, err := h.svc.List(c.Request.Context(), service.LeaseListFilter{
		Engine:     c.Query("engine"),
		Role:       c.Query("role"),
		Prefix:     c.Query("prefix"),
		TokenID:    c.Query("token_id"),
		ActiveOnly: c.Query("active_only") == "true",
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	out := make([]dto.LeaseResponse, 0, len(views))
	for _, v := range views {
		out = append(out, leaseJSON(&v))
	}
	c.JSON(http.StatusOK, gin.H{"leases": out})
}

// Renew handles POST /sys/leases/renew.
func (h *LeaseHandler) Renew(c *gin.Context) {
	var req dto.LeaseRenewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	view, err := h.svc.Renew(c.Request.Context(), req.LeaseID, req.TTLSeconds)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, leaseJSON(view))
}

// RevokeOne handles POST /sys/leases/revoke/:lease_id.
func (h *LeaseHandler) RevokeOne(c *gin.Context) {
	if err := h.svc.Revoke(c.Request.Context(), c.Param("lease_id")); err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": true, "lease_id": c.Param("lease_id")})
}

// BulkRevoke handles PUT /sys/leases/revoke.
func (h *LeaseHandler) BulkRevoke(c *gin.Context) {
	var req dto.BulkLeaseRevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	result, err := h.svc.BulkRevoke(c.Request.Context(), service.BulkRevokeRequest{
		Engine:     req.Engine,
		Role:       req.Role,
		PathPrefix: req.PathPrefix,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.BulkLeaseRevokeResponse{
		Revoked:  result.Revoked,
		LeaseIDs: result.IDs,
	})
}

// RevokePrefix handles POST /sys/leases/revoke-prefix.
func (h *LeaseHandler) RevokePrefix(c *gin.Context) {
	var req struct {
		Prefix string `json:"prefix"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	result, err := h.svc.RevokePrefix(c.Request.Context(), req.Prefix)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.BulkLeaseRevokeResponse{Revoked: result.Revoked, LeaseIDs: result.IDs})
}

// Tidy handles POST /sys/leases/tidy.
func (h *LeaseHandler) Tidy(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	n, err := h.svc.Tidy(c.Request.Context(), limit)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": n})
}

func leaseJSON(v *service.LeaseView) dto.LeaseResponse {
	if v == nil {
		return dto.LeaseResponse{}
	}
	return dto.LeaseResponse{
		LeaseID:    v.ID,
		Engine:     v.Engine,
		Role:       v.Role,
		Path:       v.Path,
		TTLSeconds: v.TTLSeconds,
		ExpiresAt:  v.ExpiresAt,
		Renewable:  v.Renewable,
		Revoked:    v.Revoked,
		RevokedAt:  v.RevokedAt,
		TokenID:    v.TokenID,
	}
}
