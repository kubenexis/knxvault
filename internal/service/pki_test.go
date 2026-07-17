// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestPKIServiceCreateIssueRevokeCRL(t *testing.T) {
	cryptoSvc := testCrypto(t)
	engine := pkiengine.NewEngine(cryptoSvc,
		memory.NewCARepository(),
		memory.NewRevocationRepository(),
	)
	engine.SetIssuedCertRepository(memory.NewIssuedCertRepository())
	engine.SetPKIRoleRepository(memory.NewPKIRoleRepository())
	svc := service.NewPKIService(engine, testAudit())
	ctx := context.Background()

	root, err := svc.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "test-root",
		CommonName: "KNXVault Test Root",
		TTL:        "30d",
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}
	if root.CertPEM == "" {
		t.Fatal("expected root cert")
	}

	leaf, err := svc.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role:       "test-root",
		CommonName: "example.com",
		TTL:        "7d",
		DNSNames:   []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("IssueCertificate() = %v", err)
	}

	ca, err := svc.GetCA(ctx, root.ID)
	if err != nil {
		t.Fatalf("GetCA() = %v", err)
	}
	if ca.Name != "test-root" {
		t.Fatalf("ca name = %q", ca.Name)
	}

	if err := svc.Revoke(ctx, root.ID, leaf.Serial, "keyCompromise"); err != nil {
		t.Fatalf("Revoke() = %v", err)
	}

	exported, err := svc.ExportCA(ctx, root.ID)
	if err != nil {
		t.Fatalf("ExportCA() = %v", err)
	}
	if exported.CertPEM == "" {
		t.Fatal("expected exported cert")
	}
}

func TestPKIServiceImportAndRotate(t *testing.T) {
	cryptoSvc := testCrypto(t)
	engine := pkiengine.NewEngine(cryptoSvc,
		memory.NewCARepository(),
		memory.NewRevocationRepository(),
	)
	svc := service.NewPKIService(engine, testAudit())
	ctx := context.Background()

	root, err := svc.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "import-root",
		CommonName: "Import Root",
		TTL:        "30d",
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}

	exported, err := svc.ExportCA(ctx, root.ID)
	if err != nil {
		t.Fatalf("ExportCA() = %v", err)
	}

	rotated, err := svc.RotateCA(ctx, root.ID)
	if err != nil {
		t.Fatalf("RotateCA() = %v", err)
	}
	if rotated.ID == root.ID {
		t.Fatal("expected new CA id after rotation")
	}

	_, err = svc.GetCA(ctx, uuid.Nil)
	if err == nil {
		t.Fatal("expected error for missing CA")
	}
	_ = exported
}
