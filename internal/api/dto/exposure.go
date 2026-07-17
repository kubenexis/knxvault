// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package dto

// ExposureReportRequest is POST /sys/exposure/report.
type ExposureReportRequest struct {
	Detector    string `json:"detector" binding:"required"`
	Fingerprint string `json:"fingerprint" binding:"required"`
	SecretPath  string `json:"secret_path,omitempty"`
	LeaseID     string `json:"lease_id,omitempty"`
	Severity    string `json:"severity,omitempty"`
}
