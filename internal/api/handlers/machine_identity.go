package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/service"
)

// MachineIdentityHandler serves NHI admin endpoints.
type MachineIdentityHandler struct {
	svc *service.MachineIdentityService
}

// NewMachineIdentityHandler constructs a handler.
func NewMachineIdentityHandler(svc *service.MachineIdentityService) *MachineIdentityHandler {
	return &MachineIdentityHandler{svc: svc}
}

// List handles GET /sys/machine-identities.
func (h *MachineIdentityHandler) List(c *gin.Context) {
	ids, err := h.svc.List(c.Request.Context())
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"machine_identities": ids})
}

// Revoke handles DELETE /sys/machine-identities/:id.
func (h *MachineIdentityHandler) Revoke(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Revoke(c.Request.Context(), id); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}
