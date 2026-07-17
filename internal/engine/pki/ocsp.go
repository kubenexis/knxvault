// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"

	"github.com/kubenexis/knxvault/internal/crypto/memzero"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// HandleOCSP processes a DER-encoded OCSP request and returns a signed response.
func (e *Engine) HandleOCSP(ctx context.Context, caID uuid.UUID, requestDER []byte) ([]byte, error) {
	if e.caRepo == nil || e.revoked == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}
	if len(requestDER) == 0 {
		return nil, common.New(common.ErrCodeValidation, "ocsp request body is required")
	}

	ca, err := e.caRepo.GetByID(ctx, caID)
	if err != nil {
		return nil, err
	}
	issuer, err := parseCertificate([]byte(ca.CertPEM))
	if err != nil {
		return nil, err
	}

	req, err := ocsp.ParseRequest(requestDER)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "invalid ocsp request", err)
	}

	serial := req.SerialNumber.Text(16)
	status := ocsp.Good
	revokedAt := time.Time{}
	if revoked, err := e.revoked.IsRevoked(ctx, serial); err != nil {
		return nil, err
	} else if revoked {
		status = ocsp.Revoked
		revokedAt = time.Now().UTC()
	}

	caKey, err := e.decryptKey(ca.PrivateKeyEnc, ca.DEKEnc)
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(caKey)

	signer, err := parseSigner(caKey)
	if err != nil {
		return nil, err
	}

	template := ocsp.Response{
		Status:       status,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   time.Now().UTC(),
		NextUpdate:   time.Now().UTC().Add(24 * time.Hour),
	}
	if status == ocsp.Revoked {
		template.RevokedAt = revokedAt
		template.RevocationReason = ocsp.Unspecified
	}

	der, err := ocsp.CreateResponse(issuer, issuer, template, signer)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "create ocsp response", err)
	}
	return der, nil
}

// OCSPStatusName returns a human-readable OCSP status.
func OCSPStatusName(status int) string {
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	case ocsp.Unknown:
		return "unknown"
	default:
		return "unknown"
	}
}
