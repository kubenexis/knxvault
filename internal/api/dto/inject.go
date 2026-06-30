package dto

import "github.com/kubenexis/knxvault/internal/inject"

// InjectRenderRequest is POST /inject/render.
type InjectRenderRequest struct {
	Secrets []inject.SecretRef `json:"secrets" binding:"required"`
	Format  inject.Format      `json:"format"`
}

// InjectRenderResponse returns materialized injection payloads.
type InjectRenderResponse struct {
	Files []inject.FileEntry `json:"files,omitempty"`
	Env   []inject.EnvEntry  `json:"env,omitempty"`
}
