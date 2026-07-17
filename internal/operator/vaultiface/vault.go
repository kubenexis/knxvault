// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package vaultiface abstracts KNXVault API calls used by the operator.
package vaultiface

import (
	"context"
	"sync"
	"time"

	"github.com/kubenexis/knxvault/pkg/client"
)

// CAResult is returned after CA creation or lookup.
type CAResult struct {
	ID        string
	Name      string
	CertPEM   string
	Serial    string
	ExpiresAt string
}

// CertResult is returned after leaf issuance, renew, or CSR sign.
type CertResult struct {
	CertPEM       string
	PrivateKeyPEM string
	Serial        string
	ExpiresAt     string
	CAID          string
	CAChain       []string
}

// API is the subset of KNXVault operations the operator needs.
type API interface {
	CreateRoot(ctx context.Context, name, commonName, ttl string, keyBits int) (*CAResult, error)
	CreateIntermediate(ctx context.Context, parentName, name, commonName, ttl string, keyBits int) (*CAResult, error)
	GetCA(ctx context.Context, id string) (*CAResult, error)
	GetCAByName(ctx context.Context, name string) (*CAResult, error)
	Issue(ctx context.Context, role, commonName, ttl string, dns, ips []string, keyBits int, clientUsage bool) (*CertResult, error)
	Renew(ctx context.Context, caID, serial, ttl string) (*CertResult, error)
	SignCSR(ctx context.Context, role, csrPEM, ttl string) (*CertResult, error)
	Health(ctx context.Context) error
}

// HTTPAPI wraps pkg/client.Client with optional SA token refresh.
type HTTPAPI struct {
	C        *client.Client
	mu       sync.Mutex
	role     string
	saPath   string
	tokenTTL time.Time
}

// NewHTTP builds an API from base URL and static token.
func NewHTTP(addr, token string) *HTTPAPI {
	h := &HTTPAPI{C: client.New(addr, token)}
	if token != "" {
		h.tokenTTL = time.Now().Add(time.Hour)
		h.saPath = "" // static-only
	}
	return h
}

// NewHTTPWithSA builds an API that prefers Kubernetes SA login.
func NewHTTPWithSA(addr, staticToken, k8sRole, saTokenPath string) *HTTPAPI {
	h := &HTTPAPI{
		C:      client.New(addr, staticToken),
		role:   k8sRole,
		saPath: saTokenPath,
	}
	if h.saPath == "" {
		h.saPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	if h.role == "" {
		h.role = "knxvault-operator"
	}
	if staticToken != "" {
		h.tokenTTL = time.Now().Add(time.Hour)
	}
	return h
}

func (h *HTTPAPI) Health(ctx context.Context) error {
	_, err := h.C.Health(ctx)
	return err
}

func (h *HTTPAPI) CreateRoot(ctx context.Context, name, commonName, ttl string, keyBits int) (*CAResult, error) {
	if err := h.ensureToken(ctx); err != nil {
		return nil, err
	}
	if existing, err := h.C.PKIGetCAByName(ctx, name); err == nil && existing != nil {
		return caFrom(existing), nil
	}
	if ttl == "" {
		ttl = "87600h"
	}
	if keyBits == 0 {
		keyBits = 4096
	}
	out, err := h.C.PKICreateRoot(ctx, client.CreateRootCARequest{
		Name: name, CommonName: commonName, TTL: ttl, KeyBits: keyBits,
	})
	if err != nil {
		if existing, e2 := h.C.PKIGetCAByName(ctx, name); e2 == nil {
			return caFrom(existing), nil
		}
		return nil, err
	}
	return caFrom(out), nil
}

func (h *HTTPAPI) CreateIntermediate(ctx context.Context, parentName, name, commonName, ttl string, keyBits int) (*CAResult, error) {
	if err := h.ensureToken(ctx); err != nil {
		return nil, err
	}
	if existing, err := h.C.PKIGetCAByName(ctx, name); err == nil && existing != nil {
		return caFrom(existing), nil
	}
	if ttl == "" {
		ttl = "43800h"
	}
	if keyBits == 0 {
		keyBits = 4096
	}
	out, err := h.C.PKICreateIntermediate(ctx, client.CreateIntermediateCARequest{
		ParentName: parentName, Name: name, CommonName: commonName, TTL: ttl, KeyBits: keyBits,
	})
	if err != nil {
		if existing, e2 := h.C.PKIGetCAByName(ctx, name); e2 == nil {
			return caFrom(existing), nil
		}
		return nil, err
	}
	return caFrom(out), nil
}

func (h *HTTPAPI) GetCA(ctx context.Context, id string) (*CAResult, error) {
	if err := h.ensureToken(ctx); err != nil {
		return nil, err
	}
	out, err := h.C.PKIGetCA(ctx, id)
	if err != nil {
		return nil, err
	}
	return caFrom(out), nil
}

func (h *HTTPAPI) GetCAByName(ctx context.Context, name string) (*CAResult, error) {
	if err := h.ensureToken(ctx); err != nil {
		return nil, err
	}
	out, err := h.C.PKIGetCAByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return caFrom(out), nil
}

func (h *HTTPAPI) Issue(ctx context.Context, role, commonName, ttl string, dns, ips []string, keyBits int, clientUsage bool) (*CertResult, error) {
	if err := h.ensureToken(ctx); err != nil {
		return nil, err
	}
	if ttl == "" {
		ttl = "2160h"
	}
	if clientUsage {
		out, err := h.C.PKIIssueClient(ctx, role, commonName, ttl)
		if err != nil {
			return nil, err
		}
		return certFromIssue(out), nil
	}
	out, err := h.C.PKIIssue(ctx, client.IssueCertRequest{
		Role: role, CommonName: commonName, DNSNames: dns, IPAddresses: ips,
		TTL: ttl, KeyBits: keyBits, AutoRenew: false,
	})
	if err != nil {
		return nil, err
	}
	return certFromIssue(out), nil
}

func (h *HTTPAPI) Renew(ctx context.Context, caID, serial, ttl string) (*CertResult, error) {
	if err := h.ensureToken(ctx); err != nil {
		return nil, err
	}
	out, err := h.C.PKIRenew(ctx, client.RenewCertRequest{CAID: caID, Serial: serial, TTL: ttl})
	if err != nil {
		return nil, err
	}
	return &CertResult{
		CertPEM: out.CertPEM, PrivateKeyPEM: out.PrivateKeyPEM,
		Serial: out.Serial, ExpiresAt: out.ExpiresAt, CAID: caID,
	}, nil
}

func (h *HTTPAPI) SignCSR(ctx context.Context, role, csrPEM, ttl string) (*CertResult, error) {
	if err := h.ensureToken(ctx); err != nil {
		return nil, err
	}
	out, err := h.C.PKISignCSR(ctx, client.SignCSRRequest{Role: role, CSR: csrPEM, TTL: ttl})
	if err != nil {
		return nil, err
	}
	return &CertResult{
		CertPEM: out.CertPEM, Serial: out.Serial, ExpiresAt: out.ExpiresAt, CAChain: out.CAChain,
	}, nil
}

func caFrom(out *client.CAResponse) *CAResult {
	if out == nil {
		return nil
	}
	return &CAResult{
		ID: out.ID, Name: out.Name, CertPEM: out.CertPEM,
		Serial: out.Serial, ExpiresAt: out.ExpiresAt,
	}
}

func certFromIssue(out *client.IssueCertResponse) *CertResult {
	if out == nil {
		return nil
	}
	return &CertResult{
		CertPEM: out.CertPEM, PrivateKeyPEM: out.PrivateKeyPEM,
		Serial: out.Serial, ExpiresAt: out.ExpiresAt, CAID: out.CAID,
	}
}
