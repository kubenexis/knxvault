package controllers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/metrics"
	"github.com/kubenexis/knxvault/internal/operator/renew"
	"github.com/kubenexis/knxvault/internal/operator/secretutil"
	"github.com/kubenexis/knxvault/internal/operator/statusutil"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

// CertificateRequestReconciler handles CSR-style requests.
// When vault lacks a dedicated CSR-sign API, it issues a new cert using CN/DNS from the CSR PEM or CR fields.
type CertificateRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Vault  vaultiface.API
}

// Reconcile signs or issues based on the request.
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

	cn := cr.Spec.CommonName
	dns := append([]string(nil), cr.Spec.DNSNames...)
	if cn == "" && cr.Spec.Request != "" {
		if p, d, err := parseCSR(cr.Spec.Request); err == nil {
			cn = p
			if len(dns) == 0 {
				dns = d
			}
		}
	}
	if cn == "" {
		cn = cr.Name
	}

	role, err := ResolveVaultRole(ctx, r.Client, cr.Namespace, cr.Spec.IssuerRef)
	if err != nil {
		metrics.ErrorsTotal.WithLabelValues("certificaterequest").Inc()
		cr.Status.Conditions = statusutil.ReadyFalse(cr.Status.Conditions, "IssuerNotReady", err.Error())
		_ = r.Status().Update(ctx, &cr)
		return ctrl.Result{}, err
	}

	ttl := cr.Spec.Duration
	if ttl == "" {
		ttl = "2160h"
	}
	clientUsage := renew.IsClientUsage(cr.Spec.Usages)
	result, err := r.Vault.Issue(ctx, role, cn, ttl, dns, nil, 0, clientUsage)
	if err != nil {
		metrics.ErrorsTotal.WithLabelValues("certificaterequest").Inc()
		cr.Status.Conditions = statusutil.ReadyFalse(cr.Status.Conditions, "VaultError", err.Error())
		_ = r.Status().Update(ctx, &cr)
		return ctrl.Result{}, err
	}

	cr.Status.Certificate = result.CertPEM
	cr.Status.Serial = result.Serial
	cr.Status.NotAfter = result.ExpiresAt
	cr.Status.Conditions = statusutil.ReadyTrue(cr.Status.Conditions, "Issued", "Certificate issued (CSR fallback issue)")
	if err := r.Status().Update(ctx, &cr); err != nil {
		return ctrl.Result{}, err
	}

	if cr.Spec.SecretName != "" {
		sec := secretutil.CertOnlySecret(cr.Namespace, cr.Spec.SecretName, result.CertPEM, "")
		if err := controllerutil.SetControllerReference(&cr, sec, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
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

func parseCSR(pemData string) (cn string, dns []string, err error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", nil, fmt.Errorf("no PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", nil, err
	}
	return csr.Subject.CommonName, csr.DNSNames, nil
}

// SetupWithManager registers the controller.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultCertificateRequest{}).
		Complete(r)
}
