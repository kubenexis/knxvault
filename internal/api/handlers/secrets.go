// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/service"
	"github.com/kubenexis/knxvault/internal/utils"
)

// SecretsHandler serves KV secret endpoints.
type SecretsHandler struct {
	svc      *service.SecretsService
	rotation *service.RotationService
	auth     *auth.Service
}

// NewSecretsHandler constructs a SecretsHandler.
func NewSecretsHandler(svc *service.SecretsService, rotation *service.RotationService, authSvc *auth.Service) *SecretsHandler {
	return &SecretsHandler{svc: svc, rotation: rotation, auth: authSvc}
}

// Write handles POST /secrets/kv/*path.
func (h *SecretsHandler) Write(c *gin.Context) {
	path, err := secretPath(c)
	if err != nil {
		_ = c.Error(err)
		return
	}
	var req dto.KVWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	result, err := h.svc.Put(c.Request.Context(), path, req.Data, secretsengine.PutOptions{
		TTL:         req.Options.TTL,
		CasVersion:  req.Options.CasVersion,
		MaxVersions: req.Options.MaxVersions,
		Labels:      req.Labels,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, dto.KVWriteResponse{Version: result.Version})
}

// Read handles GET /secrets/kv/*path.
func (h *SecretsHandler) Read(c *gin.Context) {
	rawPath, err := secretPath(c)
	if err != nil {
		_ = c.Error(err)
		return
	}
	if c.Query("list") == "true" {
		prefix := c.Query("prefix")
		if prefix == "" {
			prefix = rawPath
		} else {
			// Sanitize query prefix the same way as path params (path traversal).
			cleaned, err := cleanSecretPath(prefix)
			if err != nil {
				_ = c.Error(err)
				return
			}
			prefix = cleaned
		}
		paths, err := h.svc.ListPaths(c.Request.Context(), prefix)
		if err != nil {
			_ = c.Error(err)
			return
		}
		paths = h.filterListPaths(c, paths)
		c.JSON(http.StatusOK, dto.KVListResponse{Paths: paths})
		return
	}

	if strings.HasSuffix(rawPath, "/metadata") {
		path := strings.TrimSuffix(rawPath, "/metadata")
		version, verErr := queryVersion(c)
		if verErr != nil {
			_ = c.Error(verErr)
			return
		}
		meta, err := h.svc.GetMetadata(c.Request.Context(), path, version)
		if err != nil {
			_ = c.Error(err)
			return
		}
		c.JSON(http.StatusOK, toMetadataResponse(meta))
		return
	}

	if strings.HasSuffix(rawPath, "/versions") {
		path := strings.TrimSuffix(rawPath, "/versions")
		versions, err := h.svc.ListVersions(c.Request.Context(), path)
		if err != nil {
			_ = c.Error(err)
			return
		}
		c.JSON(http.StatusOK, dto.KVVersionsResponse{Versions: toVersionDTOs(versions)})
		return
	}

	version, verErr := queryVersion(c)
	if verErr != nil {
		_ = c.Error(verErr)
		return
	}
	var result *secretsengine.GetResult
	if version > 0 {
		result, err = h.svc.GetVersion(c.Request.Context(), rawPath, version)
	} else {
		result, err = h.svc.Get(c.Request.Context(), rawPath)
	}
	if err != nil {
		_ = c.Error(err)
		return
	}

	resp := dto.KVReadResponse{Data: result.Data}
	resp.Metadata.Version = result.Version
	resp.Metadata.CreatedAt = result.CreatedAt
	resp.Metadata.TTL = result.TTL
	resp.Metadata.Labels = result.Labels
	c.JSON(http.StatusOK, resp)
}

// Delete handles DELETE /secrets/kv/*path.
func (h *SecretsHandler) Delete(c *gin.Context) {
	path, err := secretPath(c)
	if err != nil {
		_ = c.Error(err)
		return
	}
	if versionStr := c.Query("version"); versionStr != "" {
		version, err := strconv.Atoi(versionStr)
		if err != nil {
			_ = c.Error(err)
			return
		}
		if version < 1 {
			_ = c.Error(common.New(common.ErrCodeValidation, "version must be >= 1"))
			return
		}
		if err := h.svc.DestroyVersion(c.Request.Context(), path, version); err != nil {
			_ = c.Error(err)
			return
		}
		c.Status(http.StatusNoContent)
		return
	}

	if err := h.svc.Delete(c.Request.Context(), path); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

// PutRotation handles PUT /secrets/kv/rotation.
func (h *SecretsHandler) PutRotation(c *gin.Context) {
	if h.rotation == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": "rotation not configured"})
		return
	}
	var req dto.RotationPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	interval, err := utils.ParseTTL(req.Interval)
	if err != nil {
		_ = c.Error(err)
		return
	}
	policy := &domainsecrets.RotationPolicy{
		Path:      req.Path,
		Interval:  int64(interval.Seconds()),
		Generator: req.Generator,
		ScriptRef: req.ScriptRef,
		Enabled:   true,
	}
	if err := h.rotation.PutPolicy(c.Request.Context(), policy); err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"path": req.Path, "interval": req.Interval, "generator": req.Generator})
}

// DeleteRotation handles DELETE /secrets/kv/rotation.
func (h *SecretsHandler) DeleteRotation(c *gin.Context) {
	if h.rotation == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": "rotation not configured"})
		return
	}
	path := c.Query("path")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "path query parameter required"})
		return
	}
	if err := h.rotation.DeletePolicy(c.Request.Context(), path); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

func secretPath(c *gin.Context) (string, error) {
	return cleanSecretPath(strings.TrimPrefix(c.Param("path"), "/"))
}

func cleanSecretPath(raw string) (string, error) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", common.New(common.ErrCodeValidation, "path is required")
	}
	if strings.Contains(raw, "..") {
		return "", common.New(common.ErrCodeValidation, "path must not contain ..")
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+raw), "/")
	if cleaned == "" || cleaned == "." {
		return "", common.New(common.ErrCodeValidation, "invalid path")
	}
	return cleaned, nil
}

func queryVersion(c *gin.Context) (int, error) {
	v := c.Query("version")
	if v == "" {
		return 0, nil
	}
	version, err := strconv.Atoi(v)
	if err != nil {
		return 0, common.New(common.ErrCodeValidation, "invalid version query parameter")
	}
	if version < 0 {
		return 0, common.New(common.ErrCodeValidation, "version must be >= 0")
	}
	return version, nil
}

func toMetadataResponse(meta *secretsengine.PathMetadata) dto.KVMetadataResponse {
	return dto.KVMetadataResponse{
		Path:           meta.Path,
		CurrentVersion: meta.CurrentVersion,
		MaxVersions:    meta.MaxVersions,
		Labels:         meta.Labels,
		Versions:       toVersionDTOs(meta.Versions),
	}
}

func (h *SecretsHandler) filterListPaths(c *gin.Context, paths []string) []string {
	if h.auth == nil || len(paths) == 0 {
		return paths
	}
	principal, ok := auth.PrincipalFromContext(c.Request.Context())
	if !ok {
		return paths
	}
	filtered := make([]string, 0, len(paths))
	for _, p := range paths {
		resource := "secrets/kv/" + strings.TrimPrefix(p, "/")
		reqCtx, _ := auth.RequestContextFromContext(c.Request.Context())
		if labels, err := h.svc.LabelsForPath(c.Request.Context(), strings.TrimPrefix(p, "/")); err == nil && labels != nil {
			reqCtx.ResourceLabels = labels
		}
		ctx := auth.WithRequestContext(c.Request.Context(), reqCtx)
		if err := h.auth.AuthorizePath(ctx, principal, resource, auth.CapList); err == nil {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func toVersionDTOs(versions []secretsengine.VersionMetadata) []dto.KVVersionInfo {
	out := make([]dto.KVVersionInfo, 0, len(versions))
	for _, v := range versions {
		out = append(out, dto.KVVersionInfo{
			Version:   v.Version,
			CreatedAt: v.CreatedAt,
			Destroyed: v.Destroyed,
			TTL:       v.TTL,
		})
	}
	return out
}
