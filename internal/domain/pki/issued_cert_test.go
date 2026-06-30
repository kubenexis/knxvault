package pki_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/pki"
)

func TestIssuedCertificateNeedsRenewal(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	cert := pki.IssuedCertificate{
		ID:         uuid.New(),
		CAID:       uuid.New(),
		Role:       "app",
		Serial:     "abc",
		CommonName: "app.example.com",
		TTLSeconds: 86400,
		ExpiresAt:  now.Add(12 * time.Hour),
		AutoRenew:  true,
	}
	if !cert.NeedsRenewal(now, 24*time.Hour) {
		t.Fatal("expected cert inside grace window to need renewal")
	}
	cert.AutoRenew = false
	if cert.NeedsRenewal(now, 24*time.Hour) {
		t.Fatal("expected auto_renew=false to skip renewal")
	}
}
