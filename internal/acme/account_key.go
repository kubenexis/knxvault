// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateAccountKey creates a new P-256 ECDSA ACME account key.
func GenerateAccountKey() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ParseAccountKeyPEM loads an RSA or ECDSA private key from PEM.
func ParseAccountKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("acme account key: no PEM block")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme account key: parse EC: %w", err)
		}
		return k, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme account key: parse RSA: %w", err)
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme account key: parse PKCS8: %w", err)
		}
		switch t := k.(type) {
		case *ecdsa.PrivateKey:
			return t, nil
		case *rsa.PrivateKey:
			return t, nil
		default:
			return nil, fmt.Errorf("acme account key: unsupported PKCS8 type %T", k)
		}
	default:
		return nil, fmt.Errorf("acme account key: unsupported PEM type %q", block.Type)
	}
}

// MarshalAccountKeyPEM encodes an ACME account private key as PEM.
func MarshalAccountKeyPEM(key crypto.Signer) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("acme account key is nil")
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), nil
	default:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("acme account key: marshal PKCS8: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
}
