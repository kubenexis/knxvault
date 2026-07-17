// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package vaultiface

import (
	"testing"

	"github.com/kubenexis/knxvault/pkg/client"
)

func TestCaFromCertFromIssue(t *testing.T) {
	t.Parallel()
	if caFrom(nil) != nil {
		t.Fatal("nil")
	}
	c := caFrom(&client.CAResponse{ID: "1", Name: "n", CertPEM: "c", Serial: "s", ExpiresAt: "e"})
	if c.ID != "1" || c.Name != "n" {
		t.Fatalf("%+v", c)
	}
	if certFromIssue(nil) != nil {
		t.Fatal("nil cert")
	}
	r := certFromIssue(&client.IssueCertResponse{
		CertPEM: "C", PrivateKeyPEM: "K", Serial: "S", ExpiresAt: "E", CAID: "CA",
	})
	if r.CAID != "CA" || r.Serial != "S" {
		t.Fatalf("%+v", r)
	}
}

func TestNewHTTPStaticOnly(t *testing.T) {
	t.Parallel()
	h := NewHTTP("http://127.0.0.1:8200", "tok")
	if h.C.Token != "tok" || h.saPath != "" {
		t.Fatalf("%+v", h)
	}
	h2 := NewHTTPWithSA("http://x", "boot", "role", "/tmp/sa")
	if h2.role != "role" || h2.saPath != "/tmp/sa" {
		t.Fatalf("%+v", h2)
	}
}
