// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"
	"time"

	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestRotationServicePutPolicyRequiresRepository(t *testing.T) {
	svc := service.NewRotationService(nil, nil, nil, "")
	err := svc.PutPolicy(context.Background(), &domainsecrets.RotationPolicy{Path: "app/db"})
	if err == nil {
		t.Fatal("expected error when rotation repository not configured")
	}
}

func TestRotationServiceRunDueReturnsRotationErrors(t *testing.T) {
	policies := memory.NewRotationPolicyRepository()
	now := time.Now().UTC()
	_ = policies.Save(context.Background(), &domainsecrets.RotationPolicy{
		Path:          "app/db",
		Interval:      60,
		Generator:     domainsecrets.GeneratorRandomPassword,
		LastRotatedAt: now.Add(-2 * time.Hour),
		Enabled:       true,
	})
	secretsSvc := service.NewSecretsService(
		secretsengine.NewKVV2Engine(memory.NewSecretRepository(), testCrypto(t)),
		testAudit(),
	)
	secretsSvc.SetTenantMode(true)
	svc := service.NewRotationService(policies, secretsSvc, nil, "")
	_, err := svc.RunDue(context.Background(), now)
	if err == nil {
		t.Fatal("expected rotation errors when secrets engine not configured")
	}
}
