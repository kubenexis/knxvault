package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/auth"
)

// PolicySimulateHandler serves policy simulation (W41-04).
type PolicySimulateHandler struct {
	auth *auth.Service
}

// NewPolicySimulateHandler constructs a PolicySimulateHandler.
func NewPolicySimulateHandler(svc *auth.Service) *PolicySimulateHandler {
	return &PolicySimulateHandler{auth: svc}
}

// Simulate handles POST /sys/policy/simulate.
func (h *PolicySimulateHandler) Simulate(c *gin.Context) {
	if h == nil || h.auth == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": "auth not configured"})
		return
	}
	var req dto.PolicySimulateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	reqCtx := auth.RequestContext{
		ClientIP:       req.ClientIP,
		Namespace:      req.Namespace,
		Environment:    req.Environment,
		Cluster:        req.Cluster,
		RequestPath:    req.RequestPath,
		ResourceLabels: req.ResourceLabels,
		Resource:       req.Resource,
		Action:         req.Capability,
	}
	result := h.auth.SimulatePolicy(c.Request.Context(), req.Policies, req.Resource, req.Capability, reqCtx)
	c.JSON(http.StatusOK, dto.PolicySimulateResponse{
		Allowed:       result.Allowed,
		MatchedPolicy: result.MatchedPolicy,
		Reason:        result.Reason,
		DeniedBy:      result.DeniedBy,
	})
}
