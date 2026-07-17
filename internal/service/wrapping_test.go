// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/engine/secrets/cubbyhole"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func wrapCrypto(t *testing.T) *crypto.Service {
	t.Helper()
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 7)
	}
	s, err := crypto.NewService(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWrappingWrapUnwrapOnce(t *testing.T) {
	cubby := cubbyhole.NewEngine(memory.NewSecretRepository(), wrapCrypto(t))
	svc := service.NewWrappingService(cubby, auditsvc.NewService(memory.NewAuditRepository()))
	ctx := context.Background()
	res, err := svc.Wrap(ctx, map[string]any{"secret": "s3cr3t"}, 30*time.Second)
	if err != nil || res.Token == "" {
		t.Fatalf("Wrap: %v %+v", err, res)
	}
	data, err := svc.Unwrap(ctx, res.Token)
	if err != nil || data["secret"] != "s3cr3t" {
		t.Fatalf("Unwrap: %v %v", err, data)
	}
	if _, err := svc.Unwrap(ctx, res.Token); err == nil {
		t.Fatal("second unwrap should fail")
	}
}

func TestWrappingLookupAndExpiry(t *testing.T) {
	cubby := cubbyhole.NewEngine(memory.NewSecretRepository(), wrapCrypto(t))
	svc := service.NewWrappingService(cubby, auditsvc.NewService(memory.NewAuditRepository()))
	ctx := context.Background()
	res, err := svc.Wrap(ctx, map[string]any{"a": 1}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := svc.Lookup(ctx, res.Token)
	if err != nil || meta.TTL <= 0 {
		t.Fatalf("Lookup: %v %+v", err, meta)
	}
}
