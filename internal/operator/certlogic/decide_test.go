// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package certlogic

import (
	"testing"
	"time"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
)

func TestValidateAndDecide(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	if d := ValidateAndDecide(SpecView{}, now); d.OK {
		t.Fatal("empty invalid")
	}
	if d := ValidateAndDecide(SpecView{CommonName: "x", Delivery: v1alpha1.DeliverySecret}, now); d.OK {
		t.Fatal("secret required")
	}
	d := ValidateAndDecide(SpecView{
		CommonName: "app", SecretName: "s", SecretExists: false, Duration: "720h", RenewBefore: "24h",
	}, now)
	if !d.OK || !d.NeedIssue {
		t.Fatalf("%+v", d)
	}
	far := now.Add(60 * 24 * time.Hour).Format(time.RFC3339)
	d = ValidateAndDecide(SpecView{
		CommonName: "app", SecretName: "s", SecretExists: true, StatusNotAfter: far,
		Duration: "720h", RenewBefore: "24h",
	}, now)
	if d.NeedIssue || d.RequeueAfter <= 0 {
		t.Fatalf("%+v", d)
	}
	d = ValidateAndDecide(SpecView{CommonName: "app", Delivery: v1alpha1.DeliveryNone}, now)
	if !d.OK || d.Delivery != v1alpha1.DeliveryNone {
		t.Fatalf("%+v", d)
	}
}

func TestResolveAndPrefer(t *testing.T) {
	t.Parallel()
	if !PreferRenew("s", "c") || PreferRenew("", "c") {
		t.Fatal("prefer")
	}
	if ResolveCAID("a", "b", "c") != "a" {
		t.Fatal("a")
	}
	if ResolveCAID("", "b", "c") != "b" {
		t.Fatal("b")
	}
	if ResolveCAID("", "", "c") != "c" {
		t.Fatal("c")
	}
}
