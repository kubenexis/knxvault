package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/utils"
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
		Renewable:   record.Renewable,
	})
}

// CreateToken handles POST /auth/token/create.
func (h *AuthHandler) CreateToken(c *gin.Context) {
	var req dto.TokenCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	ttl := h.ttl
	if req.TTL != "" {
		parsed, err := utils.ParseTTL(req.TTL)
		if err != nil {
			_ = c.Error(err)
			return
		}
		ttl = parsed
	}
	renewable := true
	if req.Renewable != nil {
		renewable = *req.Renewable
	}
	token, record, err := h.auth.CreateToken(c.Request.Context(), req.Subject, req.Policies, ttl, renewable)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.LoginResponse{
		ClientToken: token,
		TTL:         int(ttl.Seconds()),
		Policies:    record.Policies,
		Renewable:   record.Renewable,
	})
}

// RenewToken handles POST /auth/token/renew.
func (h *AuthHandler) RenewToken(c *gin.Context) {
	var req dto.TokenRenewRequest
	_ = c.ShouldBindJSON(&req)
	increment := h.ttl
	if req.Increment != "" {
		parsed, err := utils.ParseTTL(req.Increment)
		if err != nil {
			_ = c.Error(err)
			return
		}
		increment = parsed
	}
	token := bearerToken(c)
	record, err := h.auth.RenewToken(c.Request.Context(), token, increment)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.LoginResponse{
		ClientToken: token,
		TTL:         int(time.Until(record.ExpiresAt).Seconds()),
		Policies:    record.Policies,
		Renewable:   record.Renewable,
	})
}

// RevokeSelfToken handles DELETE /auth/token/self.
func (h *AuthHandler) RevokeSelfToken(c *gin.Context) {
	if err := h.auth.RevokeToken(c.Request.Context(), bearerToken(c)); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

func bearerToken(c *gin.Context) string {
	authz := c.GetHeader("Authorization")
	if strings.HasPrefix(authz, "Bearer ") {
		return strings.TrimPrefix(authz, "Bearer ")
	}
	return authz
}
