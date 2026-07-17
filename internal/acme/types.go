// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto"
	"time"
)

// ChallengeType is an ACME challenge kind.
type ChallengeType string

const (
	ChallengeHTTP01 ChallengeType = "http-01"
	ChallengeDNS01  ChallengeType = "dns-01"
)

// Config configures an ACME issuer.
type Config struct {
	// DirectoryURL is the ACME directory (e.g. Let's Encrypt or Pebble).
	DirectoryURL string
	// Email for account registration.
	Email string
	// AcceptTOS must be true to create an account (explicit consent).
	AcceptTOS bool
	// PreferredChain optionally selects an alternate chain name.
	PreferredChain string
	// SkipTLSVerify is for lab/test ACME servers only (never production LE).
	SkipTLSVerify bool
	// AccountKey is a persisted account private key; if nil, a new key is generated.
	AccountKey crypto.Signer
	// Challenge types to attempt (default: http-01 then dns-01 if solvers present).
	Challenges []ChallengeType
}

// OrderRequest describes domains to certify.
type OrderRequest struct {
	CommonName  string
	DNSNames    []string
	IPAddresses []string
	// KeyBits for generated RSA leaf key (default 2048).
	KeyBits int
	// TTL is a soft hint for notAfter (ACME CA decides lifetime).
	TTL time.Duration
}

// Result is a issued certificate bundle.
type Result struct {
	CertPEM       string
	PrivateKeyPEM string
	// IssuerPEM is the intermediate/issuer cert when available.
	IssuerPEM string
	// ChainPEM is full chain leaf+intermediates.
	ChainPEM  string
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
}

// HTTP01Presenter presents HTTP-01 challenge tokens (token → keyAuth).
type HTTP01Presenter interface {
	Present(ctx context.Context, domain, token, keyAuth string) error
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
}

// DNS01Presenter presents DNS-01 TXT records.
type DNS01Presenter interface {
	// Present creates _acme-challenge.<domain> TXT = value.
	Present(ctx context.Context, domain, fqdn, value string) error
	CleanUp(ctx context.Context, domain, fqdn, value string) error
}

// Issuer issues certificates (ACME or self-signed).
type Issuer interface {
	Issue(ctx context.Context, req OrderRequest) (*Result, error)
}

// AccountKeyProvider loads/stores ACME account keys (e.g. from K8s Secret).
type AccountKeyProvider interface {
	Load(ctx context.Context) (crypto.Signer, error)
	Store(ctx context.Context, key crypto.Signer) error
}

// CAInfo is returned when probing issuer readiness (directory reachable).
type CAInfo struct {
	DirectoryURL string
	Ready        bool
	Message      string
}
