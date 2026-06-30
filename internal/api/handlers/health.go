package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
)

// ReadinessChecker reports whether dependencies are ready.
type ReadinessChecker interface {
	Ready(ctx context.Context) error
}

// HAStatusProvider exposes HA and Raft probe fields.
type HAStatusProvider interface {
	HAEnabled() bool
	IsLeader() bool
	RaftEnabled() bool
	RaftReady() bool
}

// HealthHandler serves liveness and readiness probes.
type HealthHandler struct {
	version  string
	ready    ReadinessChecker
	ha       HAStatusProvider
	isLeader func() bool
}

// NewHealthHandler constructs a HealthHandler.
func NewHealthHandler(version string, ready ReadinessChecker, ha HAStatusProvider, isLeader func() bool) *HealthHandler {
	return &HealthHandler{
		version:  version,
		ready:    ready,
		ha:       ha,
		isLeader: isLeader,
	}
}

// Live handles GET /health (liveness).
func (h *HealthHandler) Live(c *gin.Context) {
	resp := dto.HealthResponse{
		Status:  "healthy",
		Version: h.version,
	}
	h.applyHA(&resp)
	c.JSON(http.StatusOK, resp)
}

// Ready handles GET /ready (readiness).
func (h *HealthHandler) Ready(c *gin.Context) {
	if h.ready != nil {
		if err := h.ready.Ready(c.Request.Context()); err != nil {
			resp := dto.HealthResponse{
				Status:  "not_ready",
				Version: h.version,
			}
			h.applyHA(&resp)
			c.JSON(http.StatusServiceUnavailable, resp)
			return
		}
	}

	resp := dto.HealthResponse{
		Status:  "ready",
		Version: h.version,
	}
	h.applyHA(&resp)
	c.JSON(http.StatusOK, resp)
}

func (h *HealthHandler) applyHA(resp *dto.HealthResponse) {
	if h.ha != nil && h.ha.RaftEnabled() {
		resp.RaftEnabled = true
		ready := h.ha.RaftReady()
		resp.RaftReady = &ready
	}
	if h.ha == nil || !h.ha.HAEnabled() {
		return
	}
	resp.HAEnabled = true
	if h.isLeader != nil {
		leader := h.isLeader()
		resp.Leader = &leader
	}
}
