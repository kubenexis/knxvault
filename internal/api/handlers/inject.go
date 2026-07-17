// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/inject"
	"github.com/kubenexis/knxvault/internal/service"
)

// InjectHandler serves secret injection endpoints.
type InjectHandler struct {
	svc    *service.InjectService
	auth   *auth.Service
	labels kvLabelLookup
}

type kvLabelLookup interface {
	LabelsForPath(ctx context.Context, path string) (map[string]string, error)
}

// NewInjectHandler constructs an InjectHandler.
func NewInjectHandler(svc *service.InjectService, authSvc *auth.Service, labels kvLabelLookup) *InjectHandler {
	return &InjectHandler{svc: svc, auth: authSvc, labels: labels}
}

func (h *InjectHandler) lookupKVLabels(ctx context.Context, path string) (map[string]string, error) {
	if h.labels == nil {
		return nil, nil
	}
	return h.labels.LabelsForPath(ctx, path)
}

// Render handles POST /inject/render.
func (h *InjectHandler) Render(c *gin.Context) {
	var req dto.InjectRenderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	if err := h.authorizeSecretPaths(c, req.Secrets); err != nil {
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

// RecordCSIMount handles POST /inject/csi/mount-audit.
func (h *InjectHandler) RecordCSIMount(c *gin.Context) {
	var req dto.CSIMountAuditRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	if err := h.authorizeKVPaths(c, req.Paths); err != nil {
		_ = c.Error(err)
		return
	}
	if err := h.svc.RecordCSIMount(c.Request.Context(), service.CSIMountAuditRequest{
		Role:           req.Role,
		Namespace:      req.Namespace,
		ServiceAccount: req.ServiceAccount,
		PodName:        req.PodName,
		Paths:          req.Paths,
	}); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *InjectHandler) authorizeSecretPaths(c *gin.Context, refs []inject.SecretRef) error {
	if h.auth == nil {
		return nil
	}
	principal, ok := auth.PrincipalFromContext(c.Request.Context())
	if !ok {
		return common.New(common.ErrCodeUnauthorized, "unauthenticated")
	}
	for _, ref := range refs {
		path := strings.TrimPrefix(strings.TrimSpace(ref.Path), "/")
		if path == "" {
			return common.New(common.ErrCodeValidation, "secret path is required")
		}
		ctx := c.Request.Context()
		if labels, err := h.lookupKVLabels(ctx, path); err == nil && labels != nil {
			reqCtx, ok := auth.RequestContextFromContext(ctx)
			if !ok {
				reqCtx = auth.RequestContext{}
			}
			reqCtx.ResourceLabels = labels
			ctx = auth.WithRequestContext(ctx, reqCtx)
		}
		if err := h.auth.AuthorizePath(ctx, principal, "secrets/kv/"+path, auth.CapRead); err != nil {
			return err
		}
	}
	return nil
}

func (h *InjectHandler) authorizeKVPaths(c *gin.Context, paths []string) error {
	if h.auth == nil {
		return nil
	}
	principal, ok := auth.PrincipalFromContext(c.Request.Context())
	if !ok {
		return common.New(common.ErrCodeUnauthorized, "unauthenticated")
	}
	for _, raw := range paths {
		path := strings.TrimPrefix(strings.TrimSpace(raw), "/")
		if path == "" {
			return common.New(common.ErrCodeValidation, "path is required")
		}
		ctx := c.Request.Context()
		if labels, err := h.lookupKVLabels(ctx, path); err == nil && labels != nil {
			reqCtx, ok := auth.RequestContextFromContext(ctx)
			if !ok {
				reqCtx = auth.RequestContext{}
			}
			reqCtx.ResourceLabels = labels
			ctx = auth.WithRequestContext(ctx, reqCtx)
		}
		if err := h.auth.AuthorizePath(ctx, principal, "secrets/kv/"+path, auth.CapRead); err != nil {
			return err
		}
	}
	return nil
}
