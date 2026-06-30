// Package dto defines HTTP request and response models.
package dto

// HealthResponse is returned by GET /health and GET /ready.
type HealthResponse struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	Leader      *bool  `json:"leader,omitempty"`
	HAEnabled   bool   `json:"ha_enabled,omitempty"`
	RaftEnabled bool   `json:"raft_enabled,omitempty"`
	RaftReady   *bool  `json:"raft_ready,omitempty"`
}
