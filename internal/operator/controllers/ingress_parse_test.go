// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package controllers

import "testing"

func TestParseIssuerAnnotation(t *testing.T) {
	t.Parallel()
	k, n := parseIssuerAnnotation("my-iss")
	if k != "KNXVaultClusterIssuer" || n != "my-iss" {
		t.Fatalf("%s %s", k, n)
	}
	k, n = parseIssuerAnnotation("KNXVaultIssuer/app")
	if k != "KNXVaultIssuer" || n != "app" {
		t.Fatalf("%s %s", k, n)
	}
}
