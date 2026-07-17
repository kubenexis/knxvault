// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package certlogic holds pure certificate decision helpers (no k8s client).
package certlogic

import (
	"fmt"
	"time"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/renew"
)

// SpecView is the pure-input view of a certificate CR for decision logic.
type SpecView struct {
	CommonName     string
	SecretName     string
	Delivery       string
	Duration       string
	RenewBefore    string
	DNSNames       []string
	IPAddresses    []string
	Usages         []string
	KeyBits        int
	StatusSerial   string
	StatusCAID     string
	StatusNotAfter string
	SecretExists   bool
}

// Decision is the outcome of pure validation / renew decision.
type Decision struct {
	OK           bool
	InvalidMsg   string
	Delivery     string
	TTL          string
	RenewBefore  time.Duration
	NeedIssue    bool
	ClientUsage  bool
	KeyBits      int
	RequeueAfter time.Duration
	NextRenew    time.Time
}

// ValidateAndDecide validates cert spec and decides whether to issue/renew.
func ValidateAndDecide(v SpecView, now time.Time) Decision {
	d := Decision{KeyBits: v.KeyBits}
	delivery := v.Delivery
	if delivery == "" {
		delivery = v1alpha1.DeliverySecret
	}
	d.Delivery = delivery

	if v.CommonName == "" {
		d.InvalidMsg = "commonName is required"
		return d
	}
	if delivery == v1alpha1.DeliverySecret && v.SecretName == "" {
		d.InvalidMsg = "secretName required for Delivery=Secret"
		return d
	}

	rb, err := renew.ParseDuration(v.RenewBefore, renew.DefaultRenewBefore)
	if err != nil {
		d.InvalidMsg = fmt.Sprintf("invalid renewBefore: %v", err)
		return d
	}
	dur, err := renew.ParseDuration(v.Duration, renew.DefaultDuration)
	if err != nil {
		d.InvalidMsg = fmt.Sprintf("invalid duration: %v", err)
		return d
	}
	d.RenewBefore = rb
	d.TTL = v.Duration
	if d.TTL == "" {
		d.TTL = fmt.Sprintf("%dh", int(dur.Hours()))
	}
	d.ClientUsage = renew.IsClientUsage(v.Usages)
	d.OK = true

	need := renew.NeedsRenew(v.StatusNotAfter, rb, now)
	if delivery == v1alpha1.DeliverySecret && !v.SecretExists {
		need = true
	}
	d.NeedIssue = need
	if !need {
		d.RequeueAfter = renew.RequeueAfter(v.StatusNotAfter, rb, now)
		d.NextRenew = now.Add(d.RequeueAfter)
	}
	return d
}

// ResolveCAID picks ca id from issue/renew result, status, or vault name lookup.
func ResolveCAID(resultCAID, statusCAID, roleCAID string) string {
	if resultCAID != "" {
		return resultCAID
	}
	if statusCAID != "" {
		return statusCAID
	}
	return roleCAID
}

// PreferRenew reports whether vault renew should be attempted first.
func PreferRenew(serial, caID string) bool {
	return serial != "" && caID != ""
}
