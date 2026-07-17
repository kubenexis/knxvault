// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/acme"
	"github.com/kubenexis/knxvault/internal/acme/filestore"
)

func TestNeedsRenew(t *testing.T) {
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	rec := &filestore.CertRecord{NotAfter: now.Add(10 * 24 * time.Hour)}
	if !acme.NeedsRenew(rec, now, acme.RenewPolicy{RenewBefore: 30 * 24 * time.Hour}) {
		t.Fatal("expected renew")
	}
	rec.NotAfter = now.Add(60 * 24 * time.Hour)
	if acme.NeedsRenew(rec, now, acme.RenewPolicy{RenewBefore: 30 * 24 * time.Hour}) {
		t.Fatal("expected no renew")
	}
	if !acme.NeedsRenew(nil, now, acme.RenewPolicy{}) {
		t.Fatal("nil record needs renew")
	}
}

func TestRenewIfNeeded(t *testing.T) {
	now := time.Now().UTC()
	called := 0
	issue := func(ctx context.Context, req acme.OrderRequest) (*acme.Result, error) {
		called++
		return &acme.Result{CertPEM: "c", PrivateKeyPEM: "k", NotAfter: now.Add(90 * 24 * time.Hour)}, nil
	}
	rec := &filestore.CertRecord{NotAfter: now.Add(60 * 24 * time.Hour)}
	res, renewed, err := acme.RenewIfNeeded(context.Background(), rec, now, acme.RenewPolicy{RenewBefore: 30 * 24 * time.Hour}, acme.OrderRequest{CommonName: "x"}, issue)
	if err != nil || renewed || res != nil || called != 0 {
		t.Fatalf("no-op: renewed=%v called=%d err=%v", renewed, called, err)
	}
	rec.NotAfter = now.Add(10 * 24 * time.Hour)
	res, renewed, err = acme.RenewIfNeeded(context.Background(), rec, now, acme.RenewPolicy{RenewBefore: 30 * 24 * time.Hour}, acme.OrderRequest{CommonName: "x"}, issue)
	if err != nil || !renewed || res == nil || called != 1 {
		t.Fatalf("renew: %v %v %v called=%d", res, renewed, err, called)
	}
	_, _, err = acme.RenewIfNeeded(context.Background(), rec, now, acme.RenewPolicy{}, acme.OrderRequest{}, nil)
	if err == nil {
		t.Fatal("nil issue should error")
	}
	issueFail := func(ctx context.Context, req acme.OrderRequest) (*acme.Result, error) {
		return nil, fmt.Errorf("boom")
	}
	rec.NotAfter = now
	_, _, err = acme.RenewIfNeeded(context.Background(), rec, now, acme.RenewPolicy{RenewBefore: time.Hour}, acme.OrderRequest{}, issueFail)
	if err == nil {
		t.Fatal("expected issue error")
	}
}
