package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
)

// VaultCompatHandler exposes HashiCorp Vault-compatible routes for ecosystem tools.
type VaultCompatHandler struct {
	auth *AuthHandler
	pki  *PKIHandler
}

// NewVaultCompatHandler constructs a VaultCompatHandler.
func NewVaultCompatHandler(auth *AuthHandler, pki *PKIHandler) *VaultCompatHandler {
	return &VaultCompatHandler{auth: auth, pki: pki}
}

type vaultAuthResponse struct {
	Auth vaultAuthData `json:"auth"`
}

type vaultAuthData struct {
	ClientToken   string   `json:"client_token"`
	LeaseDuration int      `json:"lease_duration"`
	Renewable     bool     `json:"renewable"`
	Policies      []string `json:"policies"`
}

// LoginKubernetes handles POST /v1/auth/kubernetes (cert-manager / ESO compatibility).
func (h *VaultCompatHandler) LoginKubernetes(c *gin.Context) {
	if h.auth == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"errors": []string{"auth not configured"}})
		return
	}
	var req dto.K8sLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	token, record, err := h.auth.auth.LoginKubernetes(c.Request.Context(), req.Role, req.JWT)
	if err != nil {
		_ = c.Error(err)
		return
	}
	ttl := int(time.Until(record.ExpiresAt).Seconds())
	if ttl < 0 {
		ttl = 0
	}
	c.JSON(http.StatusOK, vaultAuthResponse{
		Auth: vaultAuthData{
			ClientToken:   token,
			LeaseDuration: ttl,
			Renewable:     true,
			Policies:      record.Policies,
		},
	})
}

type vaultSignRequest struct {
	CommonName string   `json:"common_name"`
	AltNames   string   `json:"alt_names"`
	IPSANs     string   `json:"ip_sans"`
	TTL        string   `json:"ttl"`
	Format     string   `json:"format"`
}

type vaultSignResponse struct {
	Data vaultSignData `json:"data"`
}

type vaultSignData struct {
	Certificate    string `json:"certificate"`
	PrivateKey     string `json:"private_key"`
	SerialNumber   string `json:"serial_number"`
	Expiration     int64  `json:"expiration"`
	IssuingCA      string `json:"issuing_ca,omitempty"`
	CAChain        string `json:"ca_chain,omitempty"`
	PrivateKeyType string `json:"private_key_type"`
}

// SignCertificate handles POST /v1/pki/sign/:role (cert-manager Vault issuer compatibility).
func (h *VaultCompatHandler) SignCertificate(c *gin.Context) {
	if h.pki == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"errors": []string{"pki not configured"}})
		return
	}
	var req vaultSignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	role := c.Param("role")
	dnsNames := splitVaultList(req.AltNames)
	ipAddrs := splitVaultList(req.IPSANs)
	ttl := req.TTL
	if ttl == "" {
		ttl = "720h"
	}
	result, err := h.pki.svc.IssueCertificate(c.Request.Context(), pkiengine.IssueRequest{
		Role:        role,
		CommonName:  req.CommonName,
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
		TTL:         ttl,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, vaultSignResponse{
		Data: vaultSignData{
			Certificate:    result.CertPEM,
			PrivateKey:     result.PrivateKeyPEM,
			SerialNumber:   result.Serial,
			Expiration:     result.ExpiresAt.Unix(),
			PrivateKeyType: "rsa",
		},
	})
}

func splitVaultList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}