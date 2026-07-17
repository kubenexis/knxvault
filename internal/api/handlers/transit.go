// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/service"
)

// TransitHandler serves transit EaaS APIs.
type TransitHandler struct {
	svc *service.TransitService
}

// NewTransitHandler constructs the handler.
func NewTransitHandler(svc *service.TransitService) *TransitHandler {
	return &TransitHandler{svc: svc}
}

// CreateKey handles POST /transit/keys/:name
func (h *TransitHandler) CreateKey(c *gin.Context) {
	meta, err := h.svc.CreateKey(c.Request.Context(), c.Param("name"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, meta)
}

// ReadKey handles GET /transit/keys/:name
func (h *TransitHandler) ReadKey(c *gin.Context) {
	meta, err := h.svc.ReadKey(c.Request.Context(), c.Param("name"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, meta)
}

// RotateKey handles POST /transit/keys/:name/rotate
func (h *TransitHandler) RotateKey(c *gin.Context) {
	meta, err := h.svc.RotateKey(c.Request.Context(), c.Param("name"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, meta)
}

// Encrypt handles POST /transit/encrypt/:name
func (h *TransitHandler) Encrypt(c *gin.Context) {
	var req struct {
		Plaintext  string `json:"plaintext"`
		KeyVersion int    `json:"key_version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	ct, err := h.svc.Encrypt(c.Request.Context(), c.Param("name"), req.Plaintext, req.KeyVersion)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ciphertext": ct})
}

// Decrypt handles POST /transit/decrypt/:name
func (h *TransitHandler) Decrypt(c *gin.Context) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	pt, err := h.svc.Decrypt(c.Request.Context(), c.Param("name"), req.Ciphertext)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"plaintext": pt})
}

// Rewrap handles POST /transit/rewrap/:name
func (h *TransitHandler) Rewrap(c *gin.Context) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	ct, err := h.svc.Rewrap(c.Request.Context(), c.Param("name"), req.Ciphertext)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ciphertext": ct})
}

// Sign handles POST /transit/sign/:name
func (h *TransitHandler) Sign(c *gin.Context) {
	var req struct {
		Input      string `json:"input"`
		KeyVersion int    `json:"key_version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	sig, err := h.svc.Sign(c.Request.Context(), c.Param("name"), req.Input, req.KeyVersion)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"signature": sig})
}

// Verify handles POST /transit/verify/:name
func (h *TransitHandler) Verify(c *gin.Context) {
	var req struct {
		Input     string `json:"input"`
		Signature string `json:"signature"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	ok, err := h.svc.Verify(c.Request.Context(), c.Param("name"), req.Input, req.Signature)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"valid": ok})
}

// HMAC handles POST /transit/hmac/:name
func (h *TransitHandler) HMAC(c *gin.Context) {
	var req struct {
		Input      string `json:"input"`
		KeyVersion int    `json:"key_version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	mac, err := h.svc.HMAC(c.Request.Context(), c.Param("name"), req.Input, req.KeyVersion)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"hmac": mac})
}
