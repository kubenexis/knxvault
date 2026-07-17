// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package pki provides pluggable PKI certificate issuance backends.
package pki

import (
	"context"
	"crypto/x509"
	"time"
)

// RootRequest configures root CA creation.
type RootRequest struct {
	CommonName string
	TTL        time.Duration
	KeyBits    int
}

// IntermediateRequest configures intermediate CA creation.
type IntermediateRequest struct {
	ParentCertPEM []byte
	ParentKeyPEM  []byte
	CommonName    string
	TTL           time.Duration
	KeyBits       int
}

// IssueRequest configures leaf certificate issuance.
type IssueRequest struct {
	CACertPEM   []byte
	CAKeyPEM    []byte
	CommonName  string
	DNSNames    []string
	IPAddresses []string
	TTL         time.Duration
	KeyBits     int
}

// SignCSRRequest configures signing an existing CSR with a CA.
type SignCSRRequest struct {
	CSRPEM    []byte
	CACertPEM []byte
	CAKeyPEM  []byte
	TTL       time.Duration
}

// Backend performs PKI certificate operations.
type Backend interface {
	Name() string
	CreateRoot(ctx context.Context, req RootRequest) (certPEM, keyPEM []byte, err error)
	CreateIntermediate(ctx context.Context, req IntermediateRequest) (certPEM, keyPEM []byte, err error)
	IssueCertificate(ctx context.Context, req IssueRequest) (certPEM, keyPEM []byte, err error)
	SignCSR(ctx context.Context, req SignCSRRequest) (certPEM []byte, err error)
	ParseCertificate(pem []byte) (*x509.Certificate, error)
	VerifyChain(leafPEM []byte, intermediatesPEM [][]byte) error
}
