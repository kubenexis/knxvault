// Package vaultiface abstracts KNXVault API calls used by the operator.
package vaultiface

import (
	"context"

	"github.com/kubenexis/knxvault/pkg/client"
)

// CAResult is returned after CA creation.
type CAResult struct {
	ID        string
	Name      string
	CertPEM   string
	Serial    string
	ExpiresAt string
}

// CertResult is returned after leaf issuance or renew.
type CertResult struct {
	CertPEM       string
	PrivateKeyPEM string
	Serial        string
	ExpiresAt     string
	CAID          string
}

// API is the subset of KNXVault operations the operator needs.
type API interface {
	CreateRoot(ctx context.Context, name, commonName, ttl string, keyBits int) (*CAResult, error)
	CreateIntermediate(ctx context.Context, parentName, name, commonName, ttl string, keyBits int) (*CAResult, error)
	GetCA(ctx context.Context, id string) (*CAResult, error)
	Issue(ctx context.Context, role, commonName, ttl string, dns, ips []string, keyBits int, clientUsage bool) (*CertResult, error)
	Renew(ctx context.Context, caID, serial, ttl string) (*CertResult, error)
}

// HTTPAPI wraps pkg/client.Client.
type HTTPAPI struct {
	C *client.Client
}

// NewHTTP builds an API from base URL and token.
func NewHTTP(addr, token string) *HTTPAPI {
	return &HTTPAPI{C: client.New(addr, token)}
}

func (h *HTTPAPI) CreateRoot(ctx context.Context, name, commonName, ttl string, keyBits int) (*CAResult, error) {
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
		return nil, err
	}
	return caFrom(out), nil
}

func (h *HTTPAPI) CreateIntermediate(ctx context.Context, parentName, name, commonName, ttl string, keyBits int) (*CAResult, error) {
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
		return nil, err
	}
	return caFrom(out), nil
}

func (h *HTTPAPI) GetCA(ctx context.Context, id string) (*CAResult, error) {
	out, err := h.C.PKIGetCA(ctx, id)
	if err != nil {
		return nil, err
	}
	return caFrom(out), nil
}

func (h *HTTPAPI) Issue(ctx context.Context, role, commonName, ttl string, dns, ips []string, keyBits int, clientUsage bool) (*CertResult, error) {
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
	out, err := h.C.PKIRenew(ctx, client.RenewCertRequest{CAID: caID, Serial: serial, TTL: ttl})
	if err != nil {
		return nil, err
	}
	return &CertResult{
		CertPEM: out.CertPEM, PrivateKeyPEM: out.PrivateKeyPEM,
		Serial: out.Serial, ExpiresAt: out.ExpiresAt, CAID: caID,
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
		Serial: out.Serial, ExpiresAt: out.ExpiresAt,
	}
}
