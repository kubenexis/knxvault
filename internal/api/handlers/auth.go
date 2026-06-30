package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/auth"
)

// AuthHandler serves authentication endpoints.
type AuthHandler struct {
	auth *auth.Service
	ttl  time.Duration
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(svc *auth.Service, ttl time.Duration) *AuthHandler {
	return &AuthHandler{auth: svc, ttl: ttl}
}

// LoginKubernetes handles POST /auth/kubernetes.
func (h *AuthHandler) LoginKubernetes(c *gin.Context) {
	var req dto.K8sLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	token, record, err := h.auth.LoginKubernetes(c.Request.Context(), req.Role, req.JWT)
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, dto.LoginResponse{
		ClientToken: token,
		TTL:         int(h.ttl.Seconds()),
		Policies:    record.Policies,
		Renewable:   true,
	})
}

// LoginToken handles POST /auth/token.
func (h *AuthHandler) LoginToken(c *gin.Context) {
	var req dto.TokenLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	record, err := h.auth.LoginWithToken(c.Request.Context(), req.Token)
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, dto.LoginResponse{
		ClientToken: req.Token,
		TTL:         int(time.Until(record.ExpiresAt).Seconds()),
		Policies:    record.Policies,
		Renewable:   true,
	})
}
