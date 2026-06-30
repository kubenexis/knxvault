// Package api embeds the OpenAPI specification.
package api

import _ "embed"

// OpenAPISpec is the embedded OpenAPI document.
//
//go:embed openapi.yaml
var OpenAPISpec []byte
