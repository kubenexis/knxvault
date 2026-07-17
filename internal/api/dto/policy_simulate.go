// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package dto

// PolicySimulateRequest inputs for POST /sys/policy/simulate (W41-04).
type PolicySimulateRequest struct {
	Policies       []string          `json:"policies" binding:"required"`
	Resource       string            `json:"resource" binding:"required"`
	Capability     string            `json:"capability" binding:"required"`
	ClientIP       string            `json:"client_ip,omitempty"`
	Namespace      string            `json:"namespace,omitempty"`
	Environment    string            `json:"environment,omitempty"`
	Cluster        string            `json:"cluster,omitempty"`
	RequestPath    string            `json:"request_path,omitempty"`
	ResourceLabels map[string]string `json:"resource_labels,omitempty"`
}

// PolicySimulateResponse returns simulation outcome.
type PolicySimulateResponse struct {
	Allowed       bool   `json:"allowed"`
	MatchedPolicy string `json:"matched_policy,omitempty"`
	Reason        string `json:"reason"`
	DeniedBy      string `json:"denied_by,omitempty"`
}
