// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/auth"
	vaultcompat "github.com/kubenexis/knxvault/internal/compat/vault"
	"github.com/kubenexis/knxvault/internal/domain/common"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/service"
)

// VaultCompatHandler is the HTTP adapter for the cert-manager Vault issuer profile.
// Business logic stays in auth/PKI services; Vault wire shapes live in internal/compat/vault.
type VaultCompatHandler struct {
	auth    *auth.Service
	pki     *service.PKIService
	ttl     time.Duration
	seal    SealController
	ha      HAStatusProvider
	version string
}

// NewVaultCompatHandler constructs a VaultCompatHandler.
func NewVaultCompatHandler(authSvc *auth.Service, pkiSvc *service.PKIService, ttl time.Duration) *VaultCompatHandler {
	return &VaultCompatHandler{auth: authSvc, pki: pkiSvc, ttl: ttl, version: "knxvault"}
}

// WithHealthProbe wires seal/HA state for GET /v1/sys/health.
func (h *VaultCompatHandler) WithHealthProbe(seal SealController, ha HAStatusProvider, version string) *VaultCompatHandler {
	if h == nil {
		return h
	}
	h.seal = seal
	h.ha = ha
	if version != "" {
		h.version = version
	}
	return h
}

// SysHealth handles GET /v1/sys/health (unauthenticated; cert-manager readiness).
func (h *VaultCompatHandler) SysHealth(c *gin.Context) {
	state := vaultcompat.HealthState{Initialized: true}
	if h.seal != nil {
		state.Sealed = h.seal.Sealed()
	} else if h.ha != nil {
		state.Sealed = h.ha.Sealed()
	}
	if h.ha != nil && h.ha.HAEnabled() {
		state.Standby = !h.ha.IsLeader()
	}
	code := vaultcompat.HealthStatusCode(state)
	body := vaultcompat.NewHealthBody(state, h.version, time.Now().UTC().Unix())
	c.JSON(code, body)
}

// LoginKubernetes handles POST /v1/auth/kubernetes/login (and custom k8s mounts).
func (h *VaultCompatHandler) LoginKubernetes(c *gin.Context) {
	var req vaultcompat.KubernetesLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	ctx := auth.WithLoginAuditContext(c.Request.Context(), c.ClientIP(), c.GetHeader("X-Request-ID"))
	token, record, err := h.auth.LoginKubernetes(ctx, req.Role, req.JWT)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, vaultAuthResponse(h, token, record))
}

// LoginAppRole handles POST /v1/auth/approle/login (cert-manager vault.auth.appRole).
func (h *VaultCompatHandler) LoginAppRole(c *gin.Context) {
	var req vaultcompat.AppRoleLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	ctx := auth.WithLoginAuditContext(c.Request.Context(), c.ClientIP(), c.GetHeader("X-Request-ID"))
	token, record, err := h.auth.LoginAppRole(ctx, req.RoleID, req.SecretID)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, vaultAuthResponse(h, token, record))
}

// LoginMount handles POST /v1/auth/:mount/login for custom auth mount paths.
// Dispatches by body shape: role_id/secret_id → AppRole; role/jwt → Kubernetes.
func (h *VaultCompatHandler) LoginMount(c *gin.Context) {
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []string{"invalid body"}})
		return
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []string{"invalid JSON"}})
		return
	}
	method := vaultcompat.DetectLoginMethod(body)
	mount := strings.ToLower(strings.TrimSpace(c.Param("mount")))
	if method == "" {
		// Fall back to mount name hints.
		switch {
		case strings.Contains(mount, "approle"):
			method = "approle"
		case strings.Contains(mount, "kubernetes"), mount == "k8s":
			method = "kubernetes"
		default:
			c.JSON(http.StatusBadRequest, gin.H{"errors": []string{"unable to detect auth method; send jwt+role or role_id+secret_id"}})
			return
		}
	}
	// Re-bind typed request from raw body.
	c.Request.Body = io.NopCloser(strings.NewReader(string(raw)))
	switch method {
	case "approle":
		h.LoginAppRole(c)
	case "kubernetes":
		h.LoginKubernetes(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"errors": []string{"unsupported auth method"}})
	}
}

// RegisterAppRole handles POST /sys/auth/approle (admin) to register AppRole credentials.
func (h *VaultCompatHandler) RegisterAppRole(c *gin.Context) {
	var req struct {
		RoleID   string   `json:"role_id"`
		SecretID string   `json:"secret_id"`
		Subject  string   `json:"subject"`
		Policies []string `json:"policies"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	if err := h.auth.RegisterAppRole(req.RoleID, req.SecretID, req.Subject, req.Policies); err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"role_id":  req.RoleID,
		"policies": req.Policies,
		"subject":  req.Subject,
	})
}

// SignPKI handles POST /v1/pki/sign/:role and POST /v1/:mount/sign/:role.
// Request/response shapes match cert-manager's Vault Sign path.
func (h *VaultCompatHandler) SignPKI(c *gin.Context) {
	if h.pki == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"errors": []string{"pki not configured"}})
		return
	}
	role := strings.TrimSpace(c.Param("role"))
	if role == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []string{"role is required"}})
		return
	}

	var req vaultcompat.SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	result, err := h.sign(c, role, req)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, vaultcompat.NewSignSecretResponse(*result))
}

func (h *VaultCompatHandler) sign(c *gin.Context, role string, req vaultcompat.SignRequest) (*vaultcompat.SignResult, error) {
	if strings.TrimSpace(req.CSR) != "" {
		signed, err := h.pki.SignCSR(c.Request.Context(), pkiengine.SignCSRRequest{
			Role:   role,
			CSRPEM: req.CSR,
			TTL:    req.TTL,
		})
		if err != nil {
			return nil, err
		}
		return &vaultcompat.SignResult{
			Certificate: signed.CertPEM,
			CAChain:     signed.CAChain,
			Serial:      signed.Serial,
			Expiration:  vaultcompat.ExpirationUnix(signed.ExpiresAt),
		}, nil
	}

	cn := strings.TrimSpace(req.CommonName)
	if cn == "" {
		return nil, common.New(common.ErrCodeValidation, "csr or common_name is required")
	}
	issued, err := h.pki.IssueCertificate(c.Request.Context(), pkiengine.IssueRequest{
		Role:        role,
		CommonName:  cn,
		DNSNames:    req.DNSNames(),
		IPAddresses: req.IPAddresses(),
		TTL:         req.TTL,
	})
	if err != nil {
		return nil, err
	}
	// Build chain from issuing CA when available.
	chain := []string{}
	if issued.CAID != uuid.Nil {
		if ca, caErr := h.pki.GetCA(c.Request.Context(), issued.CAID); caErr == nil && ca != nil {
			chain = append(chain, ca.CertPEM)
		}
	}
	return &vaultcompat.SignResult{
		Certificate: issued.CertPEM,
		CAChain:     chain,
		Serial:      issued.Serial,
		Expiration:  vaultcompat.ExpirationUnix(issued.ExpiresAt),
		PrivateKey:  issued.PrivateKeyPEM,
	}, nil
}

func vaultAuthResponse(h *VaultCompatHandler, token string, record *auth.TokenRecord) vaultcompat.AuthResponse {
	lease := int(h.ttl.Seconds())
	renewable := true
	var policies []string
	if record != nil {
		policies = record.Policies
		renewable = record.Renewable
		if !record.ExpiresAt.IsZero() {
			secs := int(time.Until(record.ExpiresAt).Seconds())
			if secs < 0 {
				secs = 0
			}
			lease = secs
		}
	}
	return vaultcompat.NewAuthResponse(token, policies, lease, renewable)
}
