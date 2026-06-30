package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/service"
)

// SecretsHandler serves KV secret endpoints.
type SecretsHandler struct {
	svc *service.SecretsService
}

// NewSecretsHandler constructs a SecretsHandler.
func NewSecretsHandler(svc *service.SecretsService) *SecretsHandler {
	return &SecretsHandler{svc: svc}
}

// Write handles POST /secrets/kv/*path.
func (h *SecretsHandler) Write(c *gin.Context) {
	path := secretPath(c)
	var req dto.KVWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	result, err := h.svc.Put(c.Request.Context(), path, req.Data, secretsengine.PutOptions{
		TTL:        req.Options.TTL,
		CasVersion: req.Options.CasVersion,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, dto.KVWriteResponse{Version: result.Version})
}

// Read handles GET /secrets/kv/*path.
func (h *SecretsHandler) Read(c *gin.Context) {
	path := secretPath(c)
	result, err := h.svc.Get(c.Request.Context(), path)
	if err != nil {
		_ = c.Error(err)
		return
	}

	resp := dto.KVReadResponse{Data: result.Data}
	resp.Metadata.Version = result.Version
	resp.Metadata.CreatedAt = result.CreatedAt
	resp.Metadata.TTL = result.TTL
	c.JSON(http.StatusOK, resp)
}

// Delete handles DELETE /secrets/kv/*path.
func (h *SecretsHandler) Delete(c *gin.Context) {
	path := secretPath(c)
	if err := h.svc.Delete(c.Request.Context(), path); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

func secretPath(c *gin.Context) string {
	path := c.Param("path")
	return strings.TrimPrefix(path, "/")
}
