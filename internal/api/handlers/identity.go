package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/service"
)

// IdentityHandler serves entity/group/alias APIs.
type IdentityHandler struct {
	svc *service.IdentityService
}

// NewIdentityHandler constructs the handler.
func NewIdentityHandler(svc *service.IdentityService) *IdentityHandler {
	return &IdentityHandler{svc: svc}
}

// CreateEntity handles POST /identity/entity
func (h *IdentityHandler) CreateEntity(c *gin.Context) {
	var req struct {
		Name     string            `json:"name"`
		Policies []string          `json:"policies"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	ent, err := h.svc.CreateEntity(c.Request.Context(), req.Name, req.Policies, req.Metadata)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, ent)
}

// ListEntities handles GET /identity/entity
func (h *IdentityHandler) ListEntities(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"entities": h.svc.ListEntities(c.Request.Context())})
}

// GetEntity handles GET /identity/entity/:id
func (h *IdentityHandler) GetEntity(c *gin.Context) {
	ent, err := h.svc.GetEntity(c.Request.Context(), c.Param("id"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, ent)
}

// DisableEntity handles POST /identity/entity/:id/disable
func (h *IdentityHandler) DisableEntity(c *gin.Context) {
	var req struct {
		Disabled bool `json:"disabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	if err := h.svc.SetEntityDisabled(c.Request.Context(), c.Param("id"), req.Disabled); err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// CreateAlias handles POST /identity/alias
func (h *IdentityHandler) CreateAlias(c *gin.Context) {
	var req struct {
		EntityID string `json:"entity_id"`
		Mount    string `json:"mount"`
		Name     string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	a, err := h.svc.CreateAlias(c.Request.Context(), req.EntityID, req.Mount, req.Name)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, a)
}

// CreateGroup handles POST /identity/group
func (h *IdentityHandler) CreateGroup(c *gin.Context) {
	var req struct {
		Name     string   `json:"name"`
		Members  []string `json:"member_entity_ids"`
		Policies []string `json:"policies"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	g, err := h.svc.CreateGroup(c.Request.Context(), req.Name, req.Members, req.Policies)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, g)
}

// ListGroups handles GET /identity/group
func (h *IdentityHandler) ListGroups(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"groups": h.svc.ListGroups(c.Request.Context())})
}
