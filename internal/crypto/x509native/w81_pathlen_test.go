// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package x509native_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto/x509native"
)

func TestW81_IntermediateMaxPathLenZero(t *testing.T) {
	rootCert, rootKey, err := x509native.CreateRoot("Root", 48*time.Hour, 2048)
	if err != nil {
		t.Fatal(err)
	}
	intCert, _, err := x509native.CreateIntermediate(rootCert, rootKey, "Int", 24*time.Hour, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(intCert)
	if block == nil {
		t.Fatal("decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Fatalf("want MaxPathLen=0 MaxPathLenZero=true, got MaxPathLen=%d Zero=%v", cert.MaxPathLen, cert.MaxPathLenZero)
	}
}

func TestW81_RejectsWeakRSAKeyBits(t *testing.T) {
	if _, _, err := x509native.CreateRoot("Weak", time.Hour, 1024); err == nil {
		t.Fatal("expected reject for 1024-bit RSA")
	}
}
