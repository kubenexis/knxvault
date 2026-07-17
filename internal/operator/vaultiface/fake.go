// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package vaultiface

import (
	"context"
	"fmt"
	"sync"
)

// Fake is an in-memory vault for unit tests.
type Fake struct {
	mu   sync.Mutex
	CAs  map[string]*CAResult
	Fail bool
}

// NewFake constructs an empty fake vault.
func NewFake() *Fake {
	return &Fake{CAs: map[string]*CAResult{}}
}

func (f *Fake) Health(_ context.Context) error {
	if f.Fail {
		return fmt.Errorf("forced failure")
	}
	return nil
}

func (f *Fake) CreateRoot(_ context.Context, name, commonName, ttl string, keyBits int) (*CAResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail {
		return nil, fmt.Errorf("forced failure")
	}
	if existing, ok := f.CAs[name]; ok {
		return existing, nil
	}
	r := &CAResult{ID: "ca-" + name, Name: name, CertPEM: "CERT-" + commonName, Serial: "s-" + name, ExpiresAt: "2027-07-16T00:00:00Z"}
	f.CAs[name] = r
	return r, nil
}

func (f *Fake) CreateIntermediate(_ context.Context, parentName, name, commonName, ttl string, keyBits int) (*CAResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.CAs[parentName]; !ok {
		return nil, fmt.Errorf("parent %s not found", parentName)
	}
	if existing, ok := f.CAs[name]; ok {
		return existing, nil
	}
	r := &CAResult{ID: "ca-" + name, Name: name, CertPEM: "CERT-" + commonName, Serial: "s-" + name, ExpiresAt: "2027-01-01T00:00:00Z"}
	f.CAs[name] = r
	return r, nil
}

func (f *Fake) GetCA(_ context.Context, id string) (*CAResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.CAs {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (f *Fake) GetCAByName(_ context.Context, name string) (*CAResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.CAs[name]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("not found")
}

func (f *Fake) Issue(_ context.Context, role, commonName, ttl string, dns, ips []string, keyBits int, clientUsage bool) (*CertResult, error) {
	if f.Fail {
		return nil, fmt.Errorf("forced failure")
	}
	return &CertResult{
		CertPEM: "LEAF-" + commonName, PrivateKeyPEM: "KEY-" + commonName,
		Serial: "leaf-1", ExpiresAt: "2026-10-16T00:00:00Z", CAID: "ca-" + role,
	}, nil
}

func (f *Fake) Renew(_ context.Context, caID, serial, ttl string) (*CertResult, error) {
	return &CertResult{
		CertPEM: "LEAF-RENEW", PrivateKeyPEM: "KEY-RENEW",
		Serial: serial + "-r", ExpiresAt: "2026-12-01T00:00:00Z", CAID: caID,
	}, nil
}

func (f *Fake) SignCSR(_ context.Context, role, csrPEM, ttl string) (*CertResult, error) {
	if f.Fail {
		return nil, fmt.Errorf("forced failure")
	}
	if csrPEM == "" {
		return nil, fmt.Errorf("csr required")
	}
	return &CertResult{
		CertPEM: "SIGNED-CSR", Serial: "csr-1", ExpiresAt: "2026-10-16T00:00:00Z",
		CAID: "ca-" + role, CAChain: []string{"CA"},
	}, nil
}
