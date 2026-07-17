// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGatewayTLSTargets(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"listeners": []any{
				map[string]any{
					"hostname": "shop.example.com",
					"tls": map[string]any{
						"certificateRefs": []any{
							map[string]any{"name": "shop-tls"},
						},
					},
				},
				map[string]any{
					"hostname": "www.example.com",
					"tls": map[string]any{
						"certificateRefs": []any{
							map[string]any{"name": "shop-tls"},
						},
					},
				},
			},
		},
	}}
	hosts, secret := gatewayTLSTargets(gw)
	if secret != "shop-tls" {
		t.Fatalf("secret=%s", secret)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts=%v", hosts)
	}
}

func TestGatewayTLSTargetsEmpty(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]any{}}
	h, s := gatewayTLSTargets(gw)
	if h != nil || s != "" {
		t.Fatalf("%v %q", h, s)
	}
}
