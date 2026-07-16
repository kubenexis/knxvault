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
	"github.com/kubenexis/knxvault/internal/operator/metrics"
	"github.com/kubenexis/knxvault/internal/operator/renew"
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

// Reconcile issues or renews a certificate and writes a TLS Secret.
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	var cert v1alpha1.KNXVaultCertificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if cert.Spec.SecretName == "" || cert.Spec.CommonName == "" {
		cert.Status.Conditions = statusutil.ReadyFalse(cert.Status.Conditions, "InvalidSpec", "secretName and commonName are required")
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, nil
	}

	renewBefore, err := renew.ParseDuration(cert.Spec.RenewBefore, renew.DefaultRenewBefore)
	if err != nil {
		return ctrl.Result{}, err
	}
	duration, err := renew.ParseDuration(cert.Spec.Duration, renew.DefaultDuration)
	if err != nil {
		return ctrl.Result{}, err
	}
	ttl := cert.Spec.Duration
	if ttl == "" {
		ttl = fmt.Sprintf("%dh", int(duration.Hours()))
	}

	now := time.Now().UTC()
	needIssue := renew.NeedsRenew(cert.Status.NotAfter, renewBefore, now)

	// Also issue if secret missing.
	var existing corev1.Secret
	secKey := client.ObjectKey{Namespace: cert.Namespace, Name: cert.Spec.SecretName}
	if err := r.Get(ctx, secKey, &existing); err != nil {
		if apierrors.IsNotFound(err) {
			needIssue = true
		} else {
			return ctrl.Result{}, err
		}
	}

	if !needIssue {
		// Requeue near renew window.
		return ctrl.Result{RequeueAfter: renew.RequeueAfter(cert.Status.NotAfter, renewBefore, now)}, nil
	}

	role, err := ResolveVaultRole(ctx, r.Client, cert.Namespace, cert.Spec.IssuerRef)
	if err != nil {
		metrics.ErrorsTotal.WithLabelValues("certificate").Inc()
		cert.Status.Conditions = statusutil.ReadyFalse(cert.Status.Conditions, "IssuerNotReady", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, err
	}

	keyBits := cert.Spec.PrivateKey.Size
	clientUsage := renew.IsClientUsage(cert.Spec.Usages)
	var result *vaultiface.CertResult

	// Prefer renew when we have serial + caId.
	if cert.Status.Serial != "" && cert.Status.CAID != "" && cert.Status.NotAfter != "" {
		result, err = r.Vault.Renew(ctx, cert.Status.CAID, cert.Status.Serial, ttl)
		if err == nil {
			metrics.RenewsTotal.Inc()
		}
	}
	if result == nil {
		result, err = r.Vault.Issue(ctx, role, cert.Spec.CommonName, ttl, cert.Spec.DNSNames, cert.Spec.IPAddresses, keyBits, clientUsage)
		if err != nil {
			metrics.ErrorsTotal.WithLabelValues("certificate").Inc()
			cert.Status.Conditions = statusutil.ReadyFalse(cert.Status.Conditions, "VaultError", err.Error())
			_ = r.Status().Update(ctx, &cert)
			logger.Error(err, "issue certificate")
			return ctrl.Result{}, err
		}
		metrics.IssuesTotal.Inc()
	}

	sec := secretutil.TLSSecret(cert.Namespace, cert.Spec.SecretName, result.CertPEM, result.PrivateKeyPEM, "", map[string]string{
		"knxvault.kubenexis.dev/certificate": cert.Name,
	})
	if err := controllerutil.SetControllerReference(&cert, sec, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}

	var current corev1.Secret
	if err := r.Get(ctx, secKey, &current); err != nil {
		if apierrors.IsNotFound(err) {
			if err := r.Create(ctx, sec); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			return ctrl.Result{}, err
		}
	} else {
		current.Data = sec.Data
		current.Type = sec.Type
		if current.Labels == nil {
			current.Labels = map[string]string{}
		}
		for k, v := range sec.Labels {
			current.Labels[k] = v
		}
		if err := r.Update(ctx, &current); err != nil {
			return ctrl.Result{}, err
		}
	}

	cert.Status.Serial = result.Serial
	cert.Status.NotAfter = result.ExpiresAt
	cert.Status.NotBefore = metav1.Now().UTC().Format(time.RFC3339)
	cert.Status.CAID = result.CAID
	cert.Status.VaultRole = role
	cert.Status.Revision++
	cert.Status.Conditions = statusutil.ReadyTrue(cert.Status.Conditions, "Issued", "TLS Secret materialised")
	if err := r.Status().Update(ctx, &cert); err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("certificate ready", "secret", cert.Spec.SecretName, "serial", result.Serial)
	return ctrl.Result{RequeueAfter: renew.RequeueAfter(cert.Status.NotAfter, renewBefore, time.Now().UTC())}, nil
}

// SetupWithManager registers the controller.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultCertificate{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
