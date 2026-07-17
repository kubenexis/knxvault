// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth

// Vault-style capability names (W41-02).
const (
	CapRead   = "read"
	CapWrite  = "write"
	CapList   = "list"
	CapDelete = "delete"
	CapSudo   = "sudo"
)

// AllCapabilities lists supported capability values.
var AllCapabilities = []string{CapRead, CapWrite, CapList, CapDelete, CapSudo}

// NormalizeCapabilities merges capabilities[] and legacy actions[] on a policy.
func NormalizeCapabilities(capabilities, actions []string) []string {
	if len(capabilities) > 0 {
		return capabilities
	}
	return actions
}
