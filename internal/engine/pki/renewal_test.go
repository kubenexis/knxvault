package pki_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestRenewCertificate(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	issued := memory.NewIssuedCertRepository()
	engine := pkiengine.NewEngine(cryptoSvc,
		memory.NewCARepository(),
		memory.NewRevocationRepository(),
	)
	engine.SetIssuedCertRepository(issued)

	ctx := context.Background()
	root, err := engine.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "renew-root",
		CommonName: "KNXVault Renew Root",
		TTL:        "30d",
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}

	leaf, err := engine.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role:       "renew-root",
		CommonName: "renew.example.com",
		TTL:        "7d",
		DNSNames:   []string{"renew.example.com"},
		AutoRenew:  true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() = %v", err)
	}

	renewed, err := engine.RenewCertificate(ctx, pkiengine.RenewRequest{
		CAID:   root.ID,
		Serial: leaf.Serial,
	})
	if err != nil {
		t.Fatalf("RenewCertificate() = %v", err)
	}
	if renewed.PreviousSerial != leaf.Serial {
		t.Fatalf("PreviousSerial = %q, want %q", renewed.PreviousSerial, leaf.Serial)
	}
	if renewed.Serial == leaf.Serial {
		t.Fatal("expected a new serial after renewal")
	}
	if renewed.CertPEM == "" || renewed.PrivateKeyPEM == "" {
		t.Fatal("expected renewed cert and key")
	}

	saved, err := issued.GetBySerial(ctx, root.ID, renewed.Serial)
	if err != nil {
		t.Fatalf("GetBySerial() = %v", err)
	}
	if saved.RenewedFromSerial == nil || *saved.RenewedFromSerial != leaf.Serial {
		t.Fatalf("RenewedFromSerial = %v, want %q", saved.RenewedFromSerial, leaf.Serial)
	}
}

func TestRenewExpiring(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	issued := memory.NewIssuedCertRepository()
	engine := pkiengine.NewEngine(cryptoSvc,
		memory.NewCARepository(),
		memory.NewRevocationRepository(),
	)
	engine.SetIssuedCertRepository(issued)

	ctx := context.Background()
	root, err := engine.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "expiring-root",
		CommonName: "KNXVault Expiring Root",
		TTL:        "30d",
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}

	leaf, err := engine.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role:       "expiring-root",
		CommonName: "expiring.example.com",
		TTL:        "7d",
		AutoRenew:  true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() = %v", err)
	}

	record, err := issued.GetBySerial(ctx, root.ID, leaf.Serial)
	if err != nil {
		t.Fatalf("GetBySerial() = %v", err)
	}
	record.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	if err := issued.Save(ctx, record); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	count, err := engine.RenewExpiring(ctx, 72*time.Hour, 10)
	if err != nil {
		t.Fatalf("RenewExpiring() = %v", err)
	}
	if count != 1 {
		t.Fatalf("RenewExpiring count = %d, want 1", count)
	}
}

func TestParseRenewGrace(t *testing.T) {
	d, err := pkiengine.ParseRenewGrace("")
	if err != nil {
		t.Fatalf("ParseRenewGrace() = %v", err)
	}
	if d != 72*time.Hour {
		t.Fatalf("default grace = %v, want 72h", d)
	}

	d, err = pkiengine.ParseRenewGrace("48h")
	if err != nil {
		t.Fatalf("ParseRenewGrace(48h) = %v", err)
	}
	if d != 48*time.Hour {
		t.Fatalf("grace = %v, want 48h", d)
	}
}
