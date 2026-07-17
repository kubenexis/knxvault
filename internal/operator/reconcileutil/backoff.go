// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package reconcileutil provides reconcile result helpers (backoff + conditions taxonomy).
package reconcileutil

import (
	"math"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

// Condition reasons (taxonomy).
const (
	ReasonPendingIssuer  = "PendingIssuer"
	ReasonIssuing        = "Issuing"
	ReasonIssued         = "Issued"
	ReasonFailed         = "Failed"
	ReasonInvalidSpec    = "InvalidSpec"
	ReasonVaultError     = "VaultError"
	ReasonIssuerNotReady = "IssuerNotReady"
	ReasonCreated        = "Created"
	ReasonConfigured     = "Configured"
)

// ErrorResult requeues with exponential-ish backoff capped at max.
// attempt is 0-based failure count stored by caller (or 0).
func ErrorResult(attempt int) ctrl.Result {
	if attempt < 0 {
		attempt = 0
	}
	// 5s * 2^attempt, max 5m
	sec := 5 * math.Pow(2, float64(attempt))
	if sec > 300 {
		sec = 300
	}
	return ctrl.Result{RequeueAfter: time.Duration(sec) * time.Second}
}

// RequeueAfter wraps a duration.
func RequeueAfter(d time.Duration) ctrl.Result {
	return ctrl.Result{RequeueAfter: d}
}
