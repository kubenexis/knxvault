package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/api/dto"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/service"
)

// PKIHandler serves PKI endpoints.
type PKIHandler struct {
	svc *service.PKIService
}

// NewPKIHandler constructs a PKIHandler.
func NewPKIHandler(svc *service.PKIService) *PKIHandler {
	return &PKIHandler{svc: svc}
}

// CreateRoot handles POST /pki/root.
func (h *PKIHandler) CreateRoot(c *gin.Context) {
	var req dto.CreateRootCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	result, err := h.svc.CreateRoot(c.Request.Context(), pkiengine.CreateRootRequest{
		Name:       req.Name,
		CommonName: req.CommonName,
		TTL:        req.TTL,
		KeyBits:    req.KeyBits,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusCreated, toCAResponse(result))
}

// CreateIntermediate handles POST /pki/intermediate.
func (h *PKIHandler) CreateIntermediate(c *gin.Context) {
	var req dto.CreateIntermediateCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	result, err := h.svc.CreateIntermediate(c.Request.Context(), pkiengine.CreateIntermediateRequest{
		ParentName: req.ParentName,
		Name:       req.Name,
		CommonName: req.CommonName,
		TTL:        req.TTL,
		KeyBits:    req.KeyBits,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusCreated, toCAResponse(result))
}

// Issue handles POST /pki/issue.
func (h *PKIHandler) Issue(c *gin.Context) {
	var req dto.IssueCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	result, err := h.svc.IssueCertificate(c.Request.Context(), pkiengine.IssueRequest{
		Role:        req.Role,
		CommonName:  req.CommonName,
		DNSNames:    req.DNSNames,
		IPAddresses: req.IPAddresses,
		TTL:         req.TTL,
		KeyBits:     req.KeyBits,
		AutoRenew:   req.AutoRenew,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusCreated, dto.IssueCertResponse{
		CertPEM:       result.CertPEM,
		PrivateKeyPEM: result.PrivateKeyPEM,
		Serial:        result.Serial,
		ExpiresAt:     result.ExpiresAt.Format(time.RFC3339),
	})
}

// GetCA handles GET /pki/ca/:id.
func (h *PKIHandler) GetCA(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		_ = c.Error(err)
		return
	}

	ca, err := h.svc.GetCA(c.Request.Context(), id)
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, dto.CAResponse{
		ID:        ca.ID.String(),
		Name:      ca.Name,
		CertPEM:   ca.CertPEM,
		Serial:    ca.Serial,
		ExpiresAt: ca.ExpiresAt.Format(time.RFC3339),
	})
}

// Revoke handles POST /pki/revoke.
func (h *PKIHandler) Revoke(c *gin.Context) {
	var req dto.RevokeCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	caID, err := uuid.Parse(req.CAID)
	if err != nil {
		_ = c.Error(err)
		return
	}

	if err := h.svc.Revoke(c.Request.Context(), caID, req.Serial, req.Reason); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

// CRL handles GET /pki/crl/:id.
func (h *PKIHandler) CRL(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		_ = c.Error(err)
		return
	}

	crl, err := h.svc.GenerateCRL(c.Request.Context(), id)
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, dto.CRLResponse{CRLPEM: crl})
}

// Renew handles POST /pki/renew.
func (h *PKIHandler) Renew(c *gin.Context) {
	var req dto.RenewCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	caID, err := uuid.Parse(req.CAID)
	if err != nil {
		_ = c.Error(err)
		return
	}
	result, err := h.svc.RenewCertificate(c.Request.Context(), pkiengine.RenewRequest{
		CAID:   caID,
		Serial: req.Serial,
		TTL:    req.TTL,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.RenewCertResponse{
		PreviousSerial: result.PreviousSerial,
		CertPEM:        result.CertPEM,
		PrivateKeyPEM:  result.PrivateKeyPEM,
		Serial:         result.Serial,
		ExpiresAt:      result.ExpiresAt.Format(time.RFC3339),
	})
}

// ImportCA handles POST /pki/ca/import.
func (h *PKIHandler) ImportCA(c *gin.Context) {
	var req dto.ImportCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	result, err := h.svc.ImportCA(c.Request.Context(), pkiengine.ImportCARequest{
		Name:       req.Name,
		CommonName: req.CommonName,
		CertPEM:    req.CertPEM,
		KeyPEM:     req.KeyPEM,
		ParentName: req.ParentName,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusCreated, toCAResponse(result))
}

// ExportCA handles GET /pki/ca/:id/export.
func (h *PKIHandler) ExportCA(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	result, err := h.svc.ExportCA(c.Request.Context(), id)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.ExportCAResponse{
		ID:        result.ID.String(),
		Name:      result.Name,
		CertPEM:   result.CertPEM,
		ChainPEM:  result.ChainPEM,
		Serial:    result.Serial,
		ExpiresAt: result.ExpiresAt.Format(time.RFC3339),
	})
}

// RotateCA handles POST /pki/ca/:id/rotate.
func (h *PKIHandler) RotateCA(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	result, err := h.svc.RotateCA(c.Request.Context(), id)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusCreated, toCAResponse(result))
}

// OCSP handles POST /pki/ocsp/:id (application/ocsp-request).
func (h *PKIHandler) OCSP(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	body, err := c.GetRawData()
	if err != nil {
		_ = c.Error(err)
		return
	}
	resp, err := h.svc.HandleOCSP(c.Request.Context(), id, body)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.Data(http.StatusOK, "application/ocsp-response", resp)
}

func toCAResponse(result *pkiengine.CAResult) dto.CAResponse {
	return dto.CAResponse{
		ID:        result.ID.String(),
		Name:      result.Name,
		CertPEM:   result.CertPEM,
		Serial:    result.Serial,
		ExpiresAt: result.ExpiresAt.Format(time.RFC3339),
	}
}
