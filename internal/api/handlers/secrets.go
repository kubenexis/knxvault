package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/service"
)

// SecretsHandler serves KV secret endpoints.
type SecretsHandler struct {
	svc *service.SecretsService
}

// NewSecretsHandler constructs a SecretsHandler.
func NewSecretsHandler(svc *service.SecretsService) *SecretsHandler {
	return &SecretsHandler{svc: svc}
}

// Write handles POST /secrets/kv/*path.
func (h *SecretsHandler) Write(c *gin.Context) {
	path := secretPath(c)
	var req dto.KVWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}

	result, err := h.svc.Put(c.Request.Context(), path, req.Data, secretsengine.PutOptions{
		TTL:         req.Options.TTL,
		CasVersion:  req.Options.CasVersion,
		MaxVersions: req.Options.MaxVersions,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, dto.KVWriteResponse{Version: result.Version})
}

// Read handles GET /secrets/kv/*path.
func (h *SecretsHandler) Read(c *gin.Context) {
	rawPath := secretPath(c)
	if c.Query("list") == "true" {
		prefix := c.Query("prefix")
		if prefix == "" {
			prefix = rawPath
		}
		paths, err := h.svc.ListPaths(c.Request.Context(), prefix)
		if err != nil {
			_ = c.Error(err)
			return
		}
		c.JSON(http.StatusOK, dto.KVListResponse{Paths: paths})
		return
	}

	if strings.HasSuffix(rawPath, "/metadata") {
		path := strings.TrimSuffix(rawPath, "/metadata")
		version := queryVersion(c)
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

	version := queryVersion(c)
	var (
		result *secretsengine.GetResult
		err    error
	)
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
	c.JSON(http.StatusOK, resp)
}

// Delete handles DELETE /secrets/kv/*path.
func (h *SecretsHandler) Delete(c *gin.Context) {
	path := secretPath(c)
	if versionStr := c.Query("version"); versionStr != "" {
		version, err := strconv.Atoi(versionStr)
		if err != nil || version < 1 {
			_ = c.Error(err)
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

func secretPath(c *gin.Context) string {
	path := c.Param("path")
	return strings.TrimPrefix(path, "/")
}

func queryVersion(c *gin.Context) int {
	if v := c.Query("version"); v != "" {
		version, _ := strconv.Atoi(v)
		return version
	}
	return 0
}

func toMetadataResponse(meta *secretsengine.PathMetadata) dto.KVMetadataResponse {
	resp := dto.KVMetadataResponse{
		Path:           meta.Path,
		CurrentVersion: meta.CurrentVersion,
		MaxVersions:    meta.MaxVersions,
		Versions:       toVersionDTOs(meta.Versions),
	}
	return resp
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