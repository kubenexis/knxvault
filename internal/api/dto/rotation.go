// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package dto

// RotationPolicyRequest configures scheduled KV rotation.
type RotationPolicyRequest struct {
	Path      string `json:"path" binding:"required"`
	Interval  string `json:"interval" binding:"required"`
	Generator string `json:"generator" binding:"required"`
	ScriptRef string `json:"script_ref,omitempty"`
}
