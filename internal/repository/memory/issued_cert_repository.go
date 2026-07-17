// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/pki"
)

// IssuedCertRepository is an in-memory issued certificate store.
type IssuedCertRepository struct {
	mu    sync.Mutex
	certs map[string]*pki.IssuedCertificate
}

// NewIssuedCertRepository constructs an empty IssuedCertRepository.
func NewIssuedCertRepository() *IssuedCertRepository {
	return &IssuedCertRepository{certs: make(map[string]*pki.IssuedCertificate)}
}

func certKey(caID uuid.UUID, serial string) string {
	return caID.String() + ":" + serial
}

// Save stores an issued certificate record.
func (r *IssuedCertRepository) Save(_ context.Context, cert *pki.IssuedCertificate) error {
	if err := cert.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid issued certificate", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *cert
	r.certs[certKey(cert.CAID, cert.Serial)] = &stored
	return nil
}

// GetBySerial returns an issued certificate by CA and serial.
func (r *IssuedCertRepository) GetBySerial(_ context.Context, caID uuid.UUID, serial string) (*pki.IssuedCertificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cert, ok := r.certs[certKey(caID, serial)]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "issued certificate not found")
	}
	copy := *cert
	return &copy, nil
}

// List returns all issued certificate records.
func (r *IssuedCertRepository) List(_ context.Context) ([]*pki.IssuedCertificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*pki.IssuedCertificate, 0, len(r.certs))
	for _, cert := range r.certs {
		copy := *cert
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CAID == out[j].CAID {
			return out[i].Serial < out[j].Serial
		}
		return out[i].CAID.String() < out[j].CAID.String()
	})
	return out, nil
}

// ListExpiring returns auto-renew certs expiring before the given time.
func (r *IssuedCertRepository) ListExpiring(_ context.Context, before time.Time, limit int) ([]*pki.IssuedCertificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	var out []*pki.IssuedCertificate
	for _, cert := range r.certs {
		if !cert.AutoRenew {
			continue
		}
		if cert.ExpiresAt.After(before) {
			continue
		}
		copy := *cert
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ExpiresAt.Before(out[j].ExpiresAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
