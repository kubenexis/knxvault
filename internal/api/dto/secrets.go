// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package dto

import "time"

// KVWriteRequest is POST /secrets/kv/:path.
type KVWriteRequest struct {
	Data    map[string]any    `json:"data" binding:"required"`
	Labels  map[string]string `json:"labels,omitempty"`
	Options struct {
		TTL         string `json:"ttl,omitempty"`
		CasVersion  *int   `json:"cas_version,omitempty"`
		MaxVersions int    `json:"max_versions,omitempty"`
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
		Version   int               `json:"version"`
		CreatedAt time.Time         `json:"created_at"`
		TTL       string            `json:"ttl,omitempty"`
		Labels    map[string]string `json:"labels,omitempty"`
	} `json:"metadata"`
}

// KVListResponse lists secret paths under a prefix.
type KVListResponse struct {
	Paths []string `json:"paths"`
}

// KVVersionInfo describes a secret version.
type KVVersionInfo struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Destroyed bool      `json:"destroyed"`
	TTL       string    `json:"ttl,omitempty"`
}

// KVVersionsResponse lists versions for a path.
type KVVersionsResponse struct {
	Versions []KVVersionInfo `json:"versions"`
}

// KVMetadataResponse returns path metadata.
type KVMetadataResponse struct {
	Path           string            `json:"path"`
	CurrentVersion int               `json:"current_version"`
	MaxVersions    int               `json:"max_versions"`
	Labels         map[string]string `json:"labels,omitempty"`
	Versions       []KVVersionInfo   `json:"versions"`
}
