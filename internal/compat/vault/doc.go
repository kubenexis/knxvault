// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package vault implements the HashiCorp Vault product profile used by
// cert-manager's built-in Vault issuer.
//
// Design: core KNXVault services remain the only business logic. This package
// maps Vault-shaped HTTP requests/responses (and status codes) onto those
// services. Other product profiles (e.g. ACME-like, future issuers) should live
// as sibling packages under internal/compat and reuse the same service façade.
//
// Scope (cert-manager Vault issuer profile):
//   - GET  /v1/sys/health
//   - POST /v1/auth/<mount>/login  (kubernetes, approle; token auth uses X-Vault-Token)
//   - POST /v1/<mount>/sign/<role> (CSR sign; path defaults to pki/sign/:role)
package vault
