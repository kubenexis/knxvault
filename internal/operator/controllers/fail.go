// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	ctrl "sigs.k8s.io/controller-runtime"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/metrics"
	"github.com/kubenexis/knxvault/internal/operator/reconcileutil"
	"github.com/kubenexis/knxvault/internal/operator/statusutil"
)

// failCert records a certificate reconcile failure and returns a backoff Result.
func failCert(cert *v1alpha1.KNXVaultCertificate, controller, reason, msg string) ctrl.Result {
	metrics.ErrorsTotal.WithLabelValues(controller).Inc()
	cert.Status.Conditions = statusutil.ReadyFalse(cert.Status.Conditions, reason, msg)
	cert.Status.FailureCount++
	cert.Status.LastFailure = msg
	return reconcileutil.ErrorResult(cert.Status.FailureCount)
}
