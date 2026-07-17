// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"crypto/x509"

	"github.com/kubenexis/knxvault/internal/crypto/x509native"
)

const backendNative = "native"

// NativeBackend issues certificates using Go crypto/x509.
type NativeBackend struct{}

// NewNativeBackend constructs a native PKI backend.
func NewNativeBackend() *NativeBackend {
	return &NativeBackend{}
}

// Name returns the backend identifier.
func (b *NativeBackend) Name() string {
	return backendNative
}

// CreateRoot creates a self-signed root CA.
func (b *NativeBackend) CreateRoot(_ context.Context, req RootRequest) (certPEM, keyPEM []byte, err error) {
	if err := ValidateCommonName(req.CommonName); err != nil {
		return nil, nil, err
	}
	return x509native.CreateRoot(req.CommonName, req.TTL, req.KeyBits)
}

// CreateIntermediate signs an intermediate CA certificate.
func (b *NativeBackend) CreateIntermediate(_ context.Context, req IntermediateRequest) (certPEM, keyPEM []byte, err error) {
	if err := ValidateCommonName(req.CommonName); err != nil {
		return nil, nil, err
	}
	return x509native.CreateIntermediate(req.ParentCertPEM, req.ParentKeyPEM, req.CommonName, req.TTL, req.KeyBits)
}

// IssueCertificate signs a leaf certificate.
func (b *NativeBackend) IssueCertificate(_ context.Context, req IssueRequest) (certPEM, keyPEM []byte, err error) {
	if err := ValidateCommonName(req.CommonName); err != nil {
		return nil, nil, err
	}
	return x509native.IssueCertificate(req.CACertPEM, req.CAKeyPEM, req.CommonName, req.DNSNames, req.IPAddresses, req.TTL, req.KeyBits)
}

// SignCSR signs a PEM CSR with the given CA certificate and key.
func (b *NativeBackend) SignCSR(ctx context.Context, req SignCSRRequest) (certPEM []byte, err error) {
	return x509native.SignCSR(req.CSRPEM, req.CACertPEM, req.CAKeyPEM, req.TTL)
}

// ParseCertificate decodes a PEM certificate.
func (b *NativeBackend) ParseCertificate(pem []byte) (*x509.Certificate, error) {
	return x509native.ParseCertificate(pem)
}

// VerifyChain validates a certificate chain.
func (b *NativeBackend) VerifyChain(leafPEM []byte, intermediatesPEM [][]byte) error {
	return x509native.VerifyChain(leafPEM, intermediatesPEM)
}
