package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/auth"
)

// SysHandler serves system endpoints.
type SysHandler struct {
	auth *auth.Service
}

// NewSysHandler constructs a SysHandler.
func NewSysHandler(svc *auth.Service) *SysHandler {
	return &SysHandler{auth: svc}
}

// Capabilities handles GET /sys/capabilities.
func (h *SysHandler) Capabilities(c *gin.Context) {
	principal, ok := auth.PrincipalFromContext(c.Request.Context())
	if !ok || h.auth == nil {
		c.JSON(http.StatusOK, dto.CapabilitiesResponse{Capabilities: []string{}})
		return
	}

	c.JSON(http.StatusOK, dto.CapabilitiesResponse{
		Capabilities: h.auth.Capabilities(principal),
	})
}
