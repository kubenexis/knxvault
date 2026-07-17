// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package acme implements ACME (RFC 8555) certificate issuance for knxvault-operator
// multi-issuer support — HTTP-01 and DNS-01 challenges, plus self-signed issuance.
//
// Direct dependency: golang.org/x/crypto/acme (BSD-3-Clause, already in go.mod).
// No lego/MPL. DNS providers use raw HTTPS APIs or webhooks.
package acme
