// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

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

// CSIMountAuditRequest is POST /inject/csi/mount-audit.
type CSIMountAuditRequest struct {
	Role           string   `json:"role" binding:"required"`
	Namespace      string   `json:"namespace,omitempty"`
	ServiceAccount string   `json:"service_account,omitempty"`
	PodName        string   `json:"pod_name,omitempty"`
	Paths          []string `json:"paths" binding:"required"`
}
