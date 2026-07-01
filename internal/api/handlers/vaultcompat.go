package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/auth"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/service"
)

// VaultCompatHandler exposes HashiCorp Vault-compatible paths for cert-manager and tooling.
type VaultCompatHandler struct {
	auth *auth.Service
	pki  *service.PKIService
	ttl  time.Duration
}

// NewVaultCompatHandler constructs a VaultCompatHandler.
func NewVaultCompatHandler(authSvc *auth.Service, pkiSvc *service.PKIService, ttl time.Duration) *VaultCompatHandler {
	return &VaultCompatHandler{auth: authSvc, pki: pkiSvc, ttl: ttl}
}

type vaultK8sLoginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

// LoginKubernetes handles POST /v1/auth/kubernetes/login.
func (h *VaultCompatHandler) LoginKubernetes(c *gin.Context) {
	var req vaultK8sLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	token, record, err := h.auth.LoginKubernetes(c.Request.Context(), req.Role, req.JWT)
	if err != nil {
		_ = c.Error(err)
		return
	}
	lease := int(h.ttl.Seconds())
	if !record.ExpiresAt.IsZero() {
		lease = int(time.Until(record.ExpiresAt).Seconds())
	}
	c.JSON(http.StatusOK, gin.H{
		"request_id":     uuid.NewString(),
		"lease_id":       uuid.NewString(),
		"renewable":      true,
		"lease_duration": lease,
		"auth": gin.H{
			"client_token":   token,
			"accessor":       uuid.NewString(),
			"policies":       record.Policies,
			"lease_duration": lease,
			"renewable":      true,
		},
	})
}

type vaultSignRequest struct {
	CSR        string `json:"csr"`
	CommonName string `json:"common_name"`
	TTL        string `json:"ttl"`
}

// SignPKI handles POST /v1/pki/sign/:role for cert-manager Vault issuer compatibility.
func (h *VaultCompatHandler) SignPKI(c *gin.Context) {
	if h.pki == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"errors": []string{"pki not configured"}})
		return
	}
	role := strings.TrimSpace(c.Param("role"))
	var req vaultSignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	var (
		certPEM string
		chain   []string
	)
	if strings.TrimSpace(req.CSR) != "" {
		result, err := h.pki.SignCSR(c.Request.Context(), pkiengine.SignCSRRequest{
			Role:   role,
			CSRPEM: req.CSR,
			TTL:    req.TTL,
		})
		if err != nil {
			_ = c.Error(err)
			return
		}
		certPEM = result.CertPEM
		chain = result.CAChain
	} else {
		cn := strings.TrimSpace(req.CommonName)
		if cn == "" {
			c.JSON(http.StatusBadRequest, gin.H{"errors": []string{"csr or common_name is required"}})
			return
		}
		result, err := h.pki.IssueCertificate(c.Request.Context(), pkiengine.IssueRequest{
			Role:       role,
			CommonName: cn,
			TTL:        req.TTL,
		})
		if err != nil {
			_ = c.Error(err)
			return
		}
		certPEM = result.CertPEM
	}

	issuingCA := ""
	if len(chain) > 0 {
		issuingCA = chain[len(chain)-1]
	}
	c.JSON(http.StatusOK, gin.H{
		"request_id": uuid.NewString(),
		"lease_id":   uuid.NewString(),
		"data": gin.H{
			"certificate": certPEM,
			"ca_chain":    chain,
			"issuing_ca":  issuingCA,
		},
	})
}
