// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package vaultstore is a placeholder for optional ACME state in knxvault (M-ACME-2 / W60-16).
//
// ADR-0010: M-ACME-1 uses filesystem (CLI) and Kubernetes Secrets (operator) only.
// When implemented, this package will provide an AccountKeyProvider / cert state
// backend that stores encrypted blobs via the knxvault HTTP API under an admin path.
//
// Do not use in production until W60-16 lands and is documented.
package vaultstore
