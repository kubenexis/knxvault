package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/service"
)

// CubbyholeHandler serves per-token private KV.
type CubbyholeHandler struct {
	svc *service.CubbyholeService
}

// NewCubbyholeHandler constructs the handler.
func NewCubbyholeHandler(svc *service.CubbyholeService) *CubbyholeHandler {
	return &CubbyholeHandler{svc: svc}
}

// Put handles PUT /cubbyhole/*path
func (h *CubbyholeHandler) Put(c *gin.Context) {
	tokenID := middleware.TokenID(c)
	if tokenID == "" {
		_ = c.Error(common.New(common.ErrCodeUnauthorized, "token required"))
		return
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		_ = c.Error(err)
		return
	}
	path := c.Param("path")
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	if err := h.svc.Put(c.Request.Context(), tokenID, path, body.Data); err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Get handles GET /cubbyhole/*path
func (h *CubbyholeHandler) Get(c *gin.Context) {
	tokenID := middleware.TokenID(c)
	if tokenID == "" {
		_ = c.Error(common.New(common.ErrCodeUnauthorized, "token required"))
		return
	}
	path := c.Param("path")
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	data, err := h.svc.Get(c.Request.Context(), tokenID, path)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// Delete handles DELETE /cubbyhole/*path
func (h *CubbyholeHandler) Delete(c *gin.Context) {
	tokenID := middleware.TokenID(c)
	if tokenID == "" {
		_ = c.Error(common.New(common.ErrCodeUnauthorized, "token required"))
		return
	}
	path := c.Param("path")
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	if err := h.svc.Delete(c.Request.Context(), tokenID, path); err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
