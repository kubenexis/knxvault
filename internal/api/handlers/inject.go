package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/inject"
	"github.com/kubenexis/knxvault/internal/service"
)

// InjectHandler serves secret injection endpoints.
type InjectHandler struct {
	svc *service.InjectService
}

// NewInjectHandler constructs an InjectHandler.
func NewInjectHandler(svc *service.InjectService) *InjectHandler {
	return &InjectHandler{svc: svc}
}

// Render handles POST /inject/render.
func (h *InjectHandler) Render(c *gin.Context) {
	var req dto.InjectRenderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	result, err := h.svc.Render(c.Request.Context(), inject.RenderRequest{
		Secrets: req.Secrets,
		Format:  req.Format,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.InjectRenderResponse{
		Files: result.Files,
		Env:   result.Env,
	})
}
