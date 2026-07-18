// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/certlogic"
	"github.com/kubenexis/knxvault/internal/operator/metrics"
	"github.com/kubenexis/knxvault/internal/operator/reconcileutil"
	"github.com/kubenexis/knxvault/internal/operator/secretutil"
	"github.com/kubenexis/knxvault/internal/operator/statusutil"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

// CertificateReconciler materializes TLS Secrets from KNXVault PKI.
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Vault  vaultiface.API
}

// Reconcile issues or renews a certificate and optionally writes a TLS Secret.
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	var cert v1alpha1.KNXVaultCertificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	view := certlogic.SpecView{
		CommonName: cert.Spec.CommonName, SecretName: cert.Spec.SecretName,
		Delivery: cert.Spec.Delivery, Duration: cert.Spec.Duration, RenewBefore: cert.Spec.RenewBefore,
		DNSNames: cert.Spec.DNSNames, IPAddresses: cert.Spec.IPAddresses, Usages: cert.Spec.Usages,
		KeyBits: cert.Spec.PrivateKey.Size, StatusSerial: cert.Status.Serial, StatusCAID: cert.Status.CAID,
		StatusNotAfter: cert.Status.NotAfter,
	}
	if view.Delivery == "" || view.Delivery == v1alpha1.DeliverySecret {
		var existing corev1.Secret
		if err := r.Get(ctx, client.ObjectKey{Namespace: cert.Namespace, Name: cert.Spec.SecretName}, &existing); err == nil {
			view.SecretExists = true
		} else if !apierrors.IsNotFound(err) && cert.Spec.SecretName != "" {
			return ctrl.Result{}, err
		}
	}

	now := time.Now().UTC()
	dec := certlogic.ValidateAndDecide(view, now)
	if !dec.OK {
		res := failCert(&cert, "certificate", reconcileutil.ReasonInvalidSpec, dec.InvalidMsg)
		_ = r.Status().Update(ctx, &cert)
		return res, nil
	}

	if !dec.NeedIssue {
		cert.Status.NextRenewTime = dec.NextRenew.Format(time.RFC3339)
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{RequeueAfter: dec.RequeueAfter}, nil
	}

	cert.Status.Conditions = statusutil.SetCondition(cert.Status.Conditions, v1alpha1.ConditionIssuing, "True", reconcileutil.ReasonIssuing, "issuing certificate")
	_ = r.Status().Update(ctx, &cert)

	resolved, err := ResolveIssuerFromRef(ctx, r.Client, cert.Namespace, cert.Spec.IssuerRef)
	if err != nil {
		res := failCert(&cert, "certificate", reconcileutil.ReasonIssuerNotReady, err.Error())
		_ = r.Status().Update(ctx, &cert)
		return res, nil
	}

	result, err := r.issueOrRenewMulti(ctx, &cert, resolved, dec)
	if err != nil {
		res := failCert(&cert, "certificate", reconcileutil.ReasonVaultError, err.Error())
		_ = r.Status().Update(ctx, &cert)
		return res, nil
	}

	roleCAID := ""
	role := resolved.VaultCA
	if resolved.Mode == v1alpha1.IssuerModeVault && role != "" && r.Vault != nil {
		if ca, e := r.Vault.GetCAByName(ctx, role); e == nil {
			roleCAID = ca.ID
		}
	}
	caID := certlogic.ResolveCAID(result.CAID, cert.Status.CAID, roleCAID)
	newRev := cert.Status.Revision + 1

	if dec.Delivery == v1alpha1.DeliverySecret {
		if err := r.applyTLSSecret(ctx, &cert, result, caID, newRev); err != nil {
			return ctrl.Result{}, err
		}
	}

	cert.Status.Serial = result.Serial
	cert.Status.NotAfter = result.ExpiresAt
	cert.Status.NotBefore = metav1.Now().UTC().Format(time.RFC3339)
	cert.Status.CAID = caID
	cert.Status.VaultRole = role
	if cert.Status.VaultRole == "" {
		cert.Status.VaultRole = resolved.Mode
	}
	cert.Status.Revision = newRev
	cert.Status.FailureCount = 0
	cert.Status.LastFailure = ""
	d2 := certlogic.ValidateAndDecide(certlogic.SpecView{
		CommonName: cert.Spec.CommonName, SecretName: cert.Spec.SecretName,
		StatusNotAfter: result.ExpiresAt, RenewBefore: cert.Spec.RenewBefore,
		Duration: cert.Spec.Duration, SecretExists: true,
	}, now)
	cert.Status.NextRenewTime = d2.NextRenew.Format(time.RFC3339)
	cert.Status.Conditions = statusutil.ReadyTrue(cert.Status.Conditions, reconcileutil.ReasonIssued, "certificate ready")
	cert.Status.Conditions = statusutil.SetCondition(cert.Status.Conditions, v1alpha1.ConditionIssuing, "False", reconcileutil.ReasonIssued, "done")
	if err := r.Status().Update(ctx, &cert); err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("certificate ready", "secret", cert.Spec.SecretName, "serial", result.Serial, "caId", caID, "delivery", dec.Delivery)
	return ctrl.Result{RequeueAfter: d2.RequeueAfter}, nil
}

func (r *CertificateReconciler) issueOrRenewMulti(ctx context.Context, cert *v1alpha1.KNXVaultCertificate, resolved v1alpha1.ResolvedIssuer, dec certlogic.Decision) (*vaultiface.CertResult, error) {
	logger := log.FromContext(ctx)
	// Renew only for vault-backed certs with caId.
	if resolved.Mode == v1alpha1.IssuerModeVault && certlogic.PreferRenew(cert.Status.Serial, cert.Status.CAID) && r.Vault != nil {
		result, err := r.Vault.Renew(ctx, cert.Status.CAID, cert.Status.Serial, dec.TTL)
		if err == nil {
			metrics.RenewsTotal.Inc()
			return result, nil
		}
		logger.Info("renew failed, falling back to issue", "err", err.Error())
	}
	result, err := IssueFromResolved(ctx, r.Client, r.Vault, cert.Namespace, resolved,
		cert.Spec.CommonName, cert.Spec.DNSNames, cert.Spec.IPAddresses, dec.TTL, dec.KeyBits, dec.ClientUsage)
	if err != nil {
		return nil, err
	}
	metrics.IssuesTotal.Inc()
	return result, nil
}

func (r *CertificateReconciler) applyTLSSecret(ctx context.Context, cert *v1alpha1.KNXVaultCertificate, result *vaultiface.CertResult, caID string, rev int) error {
	// W81-12: only overwrite Secrets already owned by this Certificate or non-existent names.
	// Reject clobbering unrelated Secrets (no controller owner ref to this cert).
	sec := secretutil.TLSSecret(cert.Namespace, cert.Spec.SecretName, result.CertPEM, result.PrivateKeyPEM, "",
		result.Serial, result.ExpiresAt, caID, rev, map[string]string{
			"knxvault.kubenexis.dev/certificate": cert.Name,
		})
	if err := controllerutil.SetControllerReference(cert, sec, r.Scheme); err != nil {
		return err
	}
	secKey := client.ObjectKey{Namespace: cert.Namespace, Name: cert.Spec.SecretName}
	var current corev1.Secret
	if err := r.Get(ctx, secKey, &current); err != nil {
		if apierrors.IsNotFound(err) {
			return r.Create(ctx, sec)
		}
		return err
	}
	if !secretOwnedByCertificate(&current, cert) {
		return fmt.Errorf("secret %q exists and is not owned by Certificate %q; refusing overwrite", cert.Spec.SecretName, cert.Name)
	}
	if current.Annotations[secretutil.AnnSerial] == result.Serial && string(current.Data[corev1.TLSCertKey]) == result.CertPEM {
		return nil
	}
	current.Data = sec.Data
	current.Type = sec.Type
	if current.Labels == nil {
		current.Labels = map[string]string{}
	}
	for k, v := range sec.Labels {
		current.Labels[k] = v
	}
	if current.Annotations == nil {
		current.Annotations = map[string]string{}
	}
	for k, v := range sec.Annotations {
		current.Annotations[k] = v
	}
	return r.Update(ctx, &current)
}

// secretOwnedByCertificate reports whether sec is controlled by cert (W81-12 / W86-03).
// Ownership is OwnerRef-only: a spoofable label must not authorize overwrite of an
// unrelated Secret that already holds private key material.
func secretOwnedByCertificate(sec *corev1.Secret, cert *v1alpha1.KNXVaultCertificate) bool {
	if sec == nil || cert == nil {
		return false
	}
	for _, ref := range sec.OwnerReferences {
		if ref.UID == cert.UID && ref.Controller != nil && *ref.Controller {
			return true
		}
	}
	return false
}

// SetupWithManager registers the controller.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultCertificate{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
