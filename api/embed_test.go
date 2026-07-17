// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"strings"
	"testing"

	"github.com/kubenexis/knxvault/api"
)

func TestOpenAPISpecEmbedded(t *testing.T) {
	if len(api.OpenAPISpec) == 0 {
		t.Fatal("OpenAPISpec is empty")
	}
	s := string(api.OpenAPISpec)
	if !strings.Contains(s, "openapi:") {
		t.Fatal("OpenAPISpec missing openapi version key")
	}
	if !strings.Contains(s, "KNXVault") {
		t.Fatal("OpenAPISpec missing product title")
	}
}
