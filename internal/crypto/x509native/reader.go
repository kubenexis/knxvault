// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package x509native provides Go-native X.509 parsing and verification.
package x509native

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCertificate decodes a PEM-encoded X.509 certificate.
func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode certificate pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

// VerifyChain validates a leaf certificate against intermediate and root PEM material.
func VerifyChain(leafPEM []byte, intermediatesPEM [][]byte) error {
	leaf, err := ParseCertificate(leafPEM)
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
	}

	roots := x509.NewCertPool()
	inters := x509.NewCertPool()
	hasRoot := false
	for _, pemBytes := range intermediatesPEM {
		cert, err := ParseCertificate(pemBytes)
		if err != nil {
			return fmt.Errorf("parse chain certificate: %w", err)
		}
		inters.AddCert(cert)
		if cert.IsCA {
			roots.AddCert(cert)
			hasRoot = true
		}
	}
	if !hasRoot {
		for _, pemBytes := range intermediatesPEM {
			cert, err := ParseCertificate(pemBytes)
			if err != nil {
				return fmt.Errorf("parse chain certificate: %w", err)
			}
			roots.AddCert(cert)
		}
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("verify chain: %w", err)
	}
	return nil
}

// ParseCRL decodes a PEM-encoded certificate revocation list.
func ParseCRL(pemBytes []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode crl pem")
	}
	return x509.ParseRevocationList(block.Bytes)
}

// BuildCertPool constructs a certificate pool from PEM-encoded certificates.
func BuildCertPool(certsPEM ...[]byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for i, pemBytes := range certsPEM {
		cert, err := ParseCertificate(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		pool.AddCert(cert)
	}
	return pool, nil
}
