// Package csi defines the Secrets Store CSI provider contract.
// First-class K8s integration — gRPC server in cmd/knxvault-csi (backlog W39-01).
package csi

import "context"

// MountRequest mirrors the Secrets Store CSI provider gRPC mount payload.
type MountRequest struct {
	TargetPath  string            `json:"target_path"`
	SecretPaths []string          `json:"secret_paths"`
	Attributes  map[string]string `json:"attributes"`
}

// MountFile is written into the pod volume.
type MountFile struct {
	Path    string `json:"path"`
	Content []byte `json:"content"`
}

// MountResponse contains files for the CSI node plugin to write.
type MountResponse struct {
	Files []MountFile `json:"files"`
}

// Provider fetches secrets for CSI volume mounts.
type Provider interface {
	Mount(ctx context.Context, req MountRequest) (*MountResponse, error)
}
