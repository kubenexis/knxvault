package controllers

import (
	"context"
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
)

// IngressReconciler creates KNXVaultCertificate CRs from annotated Ingress objects (W30-06).
type IngressReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Enabled gates the shim (env KNXVAULT_OPERATOR_INGRESS_SHIM=true).
	Enabled bool
}

// Reconcile watches Ingress TLS + annotation.
func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if !r.Enabled {
		return ctrl.Result{}, nil
	}
	logger := log.FromContext(ctx)
	var ing networkingv1.Ingress
	if err := r.Get(ctx, req.NamespacedName, &ing); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	issuerAnn, ok := ing.Annotations[v1alpha1.AnnotationIngressIssuer]
	if !ok || issuerAnn == "" {
		return ctrl.Result{}, nil
	}
	kind, name := parseIssuerAnnotation(issuerAnn)

	for _, tls := range ing.Spec.TLS {
		if tls.SecretName == "" {
			continue
		}
		cn := tls.SecretName
		dns := append([]string(nil), tls.Hosts...)
		if len(dns) > 0 {
			cn = dns[0]
		}
		certName := fmt.Sprintf("ing-%s-%s", ing.Name, tls.SecretName)
		// Keep name length reasonable.
		if len(certName) > 63 {
			certName = certName[:63]
			certName = strings.TrimRight(certName, "-")
		}

		desired := &v1alpha1.KNXVaultCertificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      certName,
				Namespace: ing.Namespace,
				Labels: map[string]string{
					"knxvault.kubenexis.dev/ingress": ing.Name,
				},
			},
			Spec: v1alpha1.KNXVaultCertificateSpec{
				SecretName: tls.SecretName,
				IssuerRef: v1alpha1.IssuerRef{
					Kind: kind,
					Name: name,
				},
				CommonName:  cn,
				DNSNames:    dns,
				Usages:      []string{"server auth"},
				Duration:    "2160h",
				RenewBefore: "720h",
			},
		}
		if err := controllerutil.SetControllerReference(&ing, desired, r.Scheme); err != nil {
			// Ingress may not be allowed as owner for CR in all versions; ignore.
			logger.Info("could not set owner reference on certificate", "err", err.Error())
		}

		var existing v1alpha1.KNXVaultCertificate
		key := client.ObjectKey{Namespace: ing.Namespace, Name: certName}
		if err := r.Get(ctx, key, &existing); err != nil {
			if apierrors.IsNotFound(err) {
				if err := r.Create(ctx, desired); err != nil {
					return ctrl.Result{}, err
				}
				logger.Info("created certificate from ingress", "certificate", certName)
				continue
			}
			return ctrl.Result{}, err
		}
		// Update hosts if changed.
		existing.Spec.DNSNames = dns
		existing.Spec.CommonName = cn
		existing.Spec.SecretName = tls.SecretName
		existing.Spec.IssuerRef = desired.Spec.IssuerRef
		if err := r.Update(ctx, &existing); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// parseIssuerAnnotation accepts "ClusterIssuer/name", "Issuer/name", or bare "name" (ClusterIssuer).
func parseIssuerAnnotation(ann string) (kind, name string) {
	parts := strings.SplitN(ann, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "KNXVaultClusterIssuer", ann
}

// SetupWithManager registers the controller when enabled.
func (r *IngressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if !r.Enabled {
		return nil
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1.Ingress{}).
		Complete(r)
}
