package pki

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/utils"
)

// RenewRequest configures certificate renewal.
type RenewRequest struct {
	CAID   uuid.UUID
	Serial string
	TTL    string
}

// RenewResult contains a renewed certificate.
type RenewResult struct {
	PreviousSerial string
	CertPEM        string
	PrivateKeyPEM  string
	Serial         string
	ExpiresAt      time.Time
}

// RenewCertificate re-issues a leaf certificate from stored metadata.
func (e *Engine) RenewCertificate(ctx context.Context, req RenewRequest) (*RenewResult, error) {
	if e.issued == nil {
		return nil, common.New(common.ErrCodeInternal, "issued certificate repository not configured")
	}
	if req.Serial == "" {
		return nil, common.New(common.ErrCodeValidation, "serial is required")
	}

	record, err := e.issued.GetBySerial(ctx, req.CAID, req.Serial)
	if err != nil {
		return nil, err
	}

	ttl := fmt.Sprintf("%ds", record.TTLSeconds)
	if req.TTL != "" {
		ttl = req.TTL
	}

	result, err := e.IssueCertificate(ctx, IssueRequest{
		Role:       record.Role,
		CommonName: record.CommonName,
		DNSNames:   record.DNSNames,
		TTL:        ttl,
		AutoRenew:  record.AutoRenew,
	})
	if err != nil {
		return nil, err
	}

	prev := record.Serial
	saved, err := e.issued.GetBySerial(ctx, req.CAID, result.Serial)
	if err != nil {
		return nil, err
	}
	saved.RenewedFromSerial = &prev
	if err := e.issued.Save(ctx, saved); err != nil {
		return nil, err
	}

	return &RenewResult{
		PreviousSerial: prev,
		CertPEM:        result.CertPEM,
		PrivateKeyPEM:  result.PrivateKeyPEM,
		Serial:         result.Serial,
		ExpiresAt:      result.ExpiresAt,
	}, nil
}

// RenewExpiring renews certificates expiring within the grace window.
func (e *Engine) RenewExpiring(ctx context.Context, grace time.Duration, limit int) (int, error) {
	if e.issued == nil {
		return 0, common.New(common.ErrCodeInternal, "issued certificate repository not configured")
	}
	deadline := time.Now().UTC().Add(grace)
	expiring, err := e.issued.ListExpiring(ctx, deadline, limit)
	if err != nil {
		return 0, err
	}
	renewed := 0
	for _, cert := range expiring {
		if _, err := e.RenewCertificate(ctx, RenewRequest{
			CAID:   cert.CAID,
			Serial: cert.Serial,
		}); err != nil {
			return renewed, err
		}
		renewed++
	}
	return renewed, nil
}

// ParseRenewGrace parses a renewal grace duration string.
func ParseRenewGrace(raw string) (time.Duration, error) {
	if raw == "" {
		return 72 * time.Hour, nil
	}
	return utils.ParseTTL(raw)
}
