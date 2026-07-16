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
	"github.com/kubenexis/knxvault/internal/operator/reconcileutil"
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

	delivery := cert.Spec.Delivery
	if delivery == "" {
		delivery = v1alpha1.DeliverySecret
	}

	if cert.Spec.CommonName == "" {
		cert.Status.Conditions = statusutil.ReadyFalse(cert.Status.Conditions, reconcileutil.ReasonInvalidSpec, "commonName is required")
		cert.Status.FailureCount++
		cert.Status.LastFailure = "commonName required"
		_ = r.Status().Update(ctx, &cert)
		return reconcileutil.ErrorResult(cert.Status.FailureCount), nil
	}
	if delivery == v1alpha1.DeliverySecret && cert.Spec.SecretName == "" {
		cert.Status.Conditions = statusutil.ReadyFalse(cert.Status.Conditions, reconcileutil.ReasonInvalidSpec, "secretName required for Delivery=Secret")
		cert.Status.FailureCount++
		_ = r.Status().Update(ctx, &cert)
		return reconcileutil.ErrorResult(cert.Status.FailureCount), nil
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

	if delivery == v1alpha1.DeliverySecret {
		var existing corev1.Secret
		secKey := client.ObjectKey{Namespace: cert.Namespace, Name: cert.Spec.SecretName}
		if err := r.Get(ctx, secKey, &existing); err != nil {
			if apierrors.IsNotFound(err) {
				needIssue = true
			} else {
				return ctrl.Result{}, err
			}
		} else if existing.Annotations[secretutil.AnnSerial] != "" && existing.Annotations[secretutil.AnnSerial] == cert.Status.Serial {
			// Secret present and matches status — only renew when window hit.
		}
	}

	if !needIssue {
		next := now.Add(renew.RequeueAfter(cert.Status.NotAfter, renewBefore, now))
		cert.Status.NextRenewTime = next.Format(time.RFC3339)
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{RequeueAfter: renew.RequeueAfter(cert.Status.NotAfter, renewBefore, now)}, nil
	}

	cert.Status.Conditions = statusutil.SetCondition(cert.Status.Conditions, v1alpha1.ConditionIssuing, "True", reconcileutil.ReasonIssuing, "contacting vault")
	_ = r.Status().Update(ctx, &cert)

	role, err := ResolveVaultRole(ctx, r.Client, cert.Namespace, cert.Spec.IssuerRef)
	if err != nil {
		metrics.ErrorsTotal.WithLabelValues("certificate").Inc()
		cert.Status.Conditions = statusutil.ReadyFalse(cert.Status.Conditions, reconcileutil.ReasonIssuerNotReady, err.Error())
		cert.Status.FailureCount++
		cert.Status.LastFailure = err.Error()
		_ = r.Status().Update(ctx, &cert)
		return reconcileutil.ErrorResult(cert.Status.FailureCount), nil
	}

	keyBits := cert.Spec.PrivateKey.Size
	clientUsage := renew.IsClientUsage(cert.Spec.Usages)
	var result *vaultiface.CertResult

	if cert.Status.Serial != "" && cert.Status.CAID != "" {
		result, err = r.Vault.Renew(ctx, cert.Status.CAID, cert.Status.Serial, ttl)
		if err == nil {
			metrics.RenewsTotal.Inc()
		} else {
			logger.Info("renew failed, falling back to issue", "err", err.Error())
			result = nil
		}
	}
	if result == nil {
		result, err = r.Vault.Issue(ctx, role, cert.Spec.CommonName, ttl, cert.Spec.DNSNames, cert.Spec.IPAddresses, keyBits, clientUsage)
		if err != nil {
			metrics.ErrorsTotal.WithLabelValues("certificate").Inc()
			cert.Status.Conditions = statusutil.ReadyFalse(cert.Status.Conditions, reconcileutil.ReasonVaultError, err.Error())
			cert.Status.FailureCount++
			cert.Status.LastFailure = err.Error()
			_ = r.Status().Update(ctx, &cert)
			return reconcileutil.ErrorResult(cert.Status.FailureCount), nil
		}
		metrics.IssuesTotal.Inc()
	}

	// Prefer CAID from response.
	caID := result.CAID
	if caID == "" {
		caID = cert.Status.CAID
	}
	if caID == "" {
		if ca, e := r.Vault.GetCAByName(ctx, role); e == nil {
			caID = ca.ID
		}
	}

	newRev := cert.Status.Revision + 1
	if delivery == v1alpha1.DeliverySecret {
		sec := secretutil.TLSSecret(cert.Namespace, cert.Spec.SecretName, result.CertPEM, result.PrivateKeyPEM, "",
			result.Serial, result.ExpiresAt, caID, newRev, map[string]string{
				"knxvault.kubenexis.dev/certificate": cert.Name,
			})
		if err := controllerutil.SetControllerReference(&cert, sec, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		secKey := client.ObjectKey{Namespace: cert.Namespace, Name: cert.Spec.SecretName}
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
			// Skip update if serial annotation already matches.
			if current.Annotations[secretutil.AnnSerial] == result.Serial && string(current.Data[corev1.TLSCertKey]) == result.CertPEM {
				// already good
			} else {
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
				if err := r.Update(ctx, &current); err != nil {
					return ctrl.Result{}, err
				}
			}
		}
	}

	cert.Status.Serial = result.Serial
	cert.Status.NotAfter = result.ExpiresAt
	cert.Status.NotBefore = metav1.Now().UTC().Format(time.RFC3339)
	cert.Status.CAID = caID
	cert.Status.VaultRole = role
	cert.Status.Revision = newRev
	cert.Status.FailureCount = 0
	cert.Status.LastFailure = ""
	next := now.Add(renew.RequeueAfter(cert.Status.NotAfter, renewBefore, now))
	cert.Status.NextRenewTime = next.Format(time.RFC3339)
	cert.Status.Conditions = statusutil.ReadyTrue(cert.Status.Conditions, reconcileutil.ReasonIssued, "certificate ready")
	cert.Status.Conditions = statusutil.SetCondition(cert.Status.Conditions, v1alpha1.ConditionIssuing, "False", reconcileutil.ReasonIssued, "done")
	if err := r.Status().Update(ctx, &cert); err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("certificate ready", "secret", cert.Spec.SecretName, "serial", result.Serial, "caId", caID, "delivery", delivery)
	return ctrl.Result{RequeueAfter: renew.RequeueAfter(cert.Status.NotAfter, renewBefore, time.Now().UTC())}, nil
}

// SetupWithManager registers the controller.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultCertificate{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
