// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/metrics"
	"github.com/kubenexis/knxvault/internal/operator/reconcileutil"
	"github.com/kubenexis/knxvault/internal/operator/renew"
	"github.com/kubenexis/knxvault/internal/operator/secretutil"
	"github.com/kubenexis/knxvault/internal/operator/statusutil"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

// CertificateRequestReconciler signs CSRs via POST /pki/sign (true CSR path).
type CertificateRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Vault  vaultiface.API
}

// Reconcile signs a CSR or falls back to issue when CSR missing.
func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	var cr v1alpha1.KNXVaultCertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if cr.Status.Serial != "" && cr.Status.Certificate != "" {
		return ctrl.Result{}, nil
	}

	role, err := ResolveVaultRole(ctx, r.Client, cr.Namespace, cr.Spec.IssuerRef)
	if err != nil {
		metrics.ErrorsTotal.WithLabelValues("certificaterequest").Inc()
		cr.Status.Conditions = statusutil.ReadyFalse(cr.Status.Conditions, reconcileutil.ReasonIssuerNotReady, err.Error())
		_ = r.Status().Update(ctx, &cr)
		return reconcileutil.ErrorResult(1), nil
	}

	ttl := cr.Spec.Duration
	if ttl == "" {
		ttl = "2160h"
	}

	var result *vaultiface.CertResult
	if cr.Spec.Request != "" {
		result, err = r.Vault.SignCSR(ctx, role, cr.Spec.Request, ttl)
		if err != nil {
			metrics.ErrorsTotal.WithLabelValues("certificaterequest").Inc()
			cr.Status.Conditions = statusutil.ReadyFalse(cr.Status.Conditions, reconcileutil.ReasonVaultError, err.Error())
			_ = r.Status().Update(ctx, &cr)
			return reconcileutil.ErrorResult(2), nil
		}
	} else {
		// Fallback: issue with CN/DNS from CR fields.
		cn := cr.Spec.CommonName
		if cn == "" {
			cn = cr.Name
		}
		clientUsage := renew.IsClientUsage(cr.Spec.Usages)
		result, err = r.Vault.Issue(ctx, role, cn, ttl, cr.Spec.DNSNames, nil, 0, clientUsage)
		if err != nil {
			metrics.ErrorsTotal.WithLabelValues("certificaterequest").Inc()
			cr.Status.Conditions = statusutil.ReadyFalse(cr.Status.Conditions, reconcileutil.ReasonVaultError, err.Error())
			_ = r.Status().Update(ctx, &cr)
			return reconcileutil.ErrorResult(2), nil
		}
	}

	caPEM := ""
	if len(result.CAChain) > 0 {
		caPEM = result.CAChain[len(result.CAChain)-1]
	}
	cr.Status.Certificate = result.CertPEM
	cr.Status.Serial = result.Serial
	cr.Status.NotAfter = result.ExpiresAt
	cr.Status.CACertificate = caPEM
	cr.Status.Conditions = statusutil.ReadyTrue(cr.Status.Conditions, reconcileutil.ReasonIssued, "CSR signed or cert issued")
	if err := r.Status().Update(ctx, &cr); err != nil {
		return ctrl.Result{}, err
	}

	if cr.Spec.SecretName != "" {
		sec := secretutil.CertOnlySecret(cr.Namespace, cr.Spec.SecretName, result.CertPEM, caPEM)
		_ = controllerutil.SetControllerReference(&cr, sec, r.Scheme)
		var current corev1.Secret
		key := client.ObjectKey{Namespace: cr.Namespace, Name: cr.Spec.SecretName}
		if err := r.Get(ctx, key, &current); err != nil {
			if apierrors.IsNotFound(err) {
				if err := r.Create(ctx, sec); err != nil {
					return ctrl.Result{}, err
				}
			} else {
				return ctrl.Result{}, err
			}
		} else {
			current.Data = sec.Data
			if err := r.Update(ctx, &current); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	metrics.IssuesTotal.Inc()
	logger.Info("certificate request ready", "serial", result.Serial)
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultCertificateRequest{}).
		Complete(r)
}
