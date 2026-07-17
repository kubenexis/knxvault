package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/service"
)

// WrappingHandler serves response wrapping APIs.
type WrappingHandler struct {
	svc *service.WrappingService
}

// NewWrappingHandler constructs the handler.
func NewWrappingHandler(svc *service.WrappingService) *WrappingHandler {
	return &WrappingHandler{svc: svc}
}

// Wrap handles POST /sys/wrapping/wrap
func (h *WrappingHandler) Wrap(c *gin.Context) {
	var req struct {
		Data map[string]any `json:"data"`
		TTL  string         `json:"ttl"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	ttl := 60 * time.Second
	if req.TTL != "" {
		if d, err := time.ParseDuration(req.TTL); err == nil {
			ttl = d
		}
	}
	res, err := h.svc.Wrap(c.Request.Context(), req.Data, ttl)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// Unwrap handles POST /sys/wrapping/unwrap
func (h *WrappingHandler) Unwrap(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	data, err := h.svc.Unwrap(c.Request.Context(), req.Token)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// Lookup handles POST /sys/wrapping/lookup
func (h *WrappingHandler) Lookup(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	meta, err := h.svc.Lookup(c.Request.Context(), req.Token)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, meta)
}
