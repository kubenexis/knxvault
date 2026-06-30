package dto

import "time"

// KVWriteRequest is POST /secrets/kv/:path.
type KVWriteRequest struct {
	Data    map[string]any `json:"data" binding:"required"`
	Options struct {
		TTL        string `json:"ttl,omitempty"`
		CasVersion *int   `json:"cas_version,omitempty"`
	} `json:"options,omitempty"`
}

// KVWriteResponse is returned after a secret write.
type KVWriteResponse struct {
	Version int `json:"version"`
}

// KVReadResponse is returned for secret reads.
type KVReadResponse struct {
	Data     map[string]any `json:"data"`
	Metadata struct {
		Version   int       `json:"version"`
		CreatedAt time.Time `json:"created_at"`
		TTL       string    `json:"ttl,omitempty"`
	} `json:"metadata"`
}
