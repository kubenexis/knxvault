package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/service"
)

// LeaseHandler serves unified lease endpoints (W42-01–03).
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
	c.JSON(http.StatusOK, dto.LeaseResponse{
		LeaseID:    view.ID,
		Engine:     view.Engine,
		Role:       view.Role,
		Path:       view.Path,
		TTLSeconds: view.TTLSeconds,
		ExpiresAt:  view.ExpiresAt,
		Renewable:  view.Renewable,
		Revoked:    view.Revoked,
		RevokedAt:  view.RevokedAt,
	})
}

// List handles GET /sys/leases.
func (h *LeaseHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	views, err := h.svc.List(c.Request.Context(), service.LeaseListFilter{
		Engine:     c.Query("engine"),
		Role:       c.Query("role"),
		Prefix:     c.Query("prefix"),
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
		out = append(out, dto.LeaseResponse{
			LeaseID:    v.ID,
			Engine:     v.Engine,
			Role:       v.Role,
			Path:       v.Path,
			TTLSeconds: v.TTLSeconds,
			ExpiresAt:  v.ExpiresAt,
			Renewable:  v.Renewable,
			Revoked:    v.Revoked,
			RevokedAt:  v.RevokedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"leases": out})
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
