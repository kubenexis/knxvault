package controllers

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
)

// Gateway GVK (Gateway API).
var gatewayGVK = schema.GroupVersionKind{
	Group:   "gateway.networking.k8s.io",
	Version: "v1",
	Kind:    "Gateway",
}

// GatewayReconciler creates KNXVaultCertificate CRs from annotated Gateway objects.
// Uses unstructured client so Gateway API CRDs are optional at compile time.
type GatewayReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Enabled bool
}

// Reconcile watches Gateway TLS listeners + issuer annotation.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if !r.Enabled {
		return ctrl.Result{}, nil
	}
	logger := log.FromContext(ctx)
	gw := &unstructured.Unstructured{}
	gw.SetGroupVersionKind(gatewayGVK)
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	ann := gw.GetAnnotations()
	if ann == nil {
		return ctrl.Result{}, nil
	}
	issuerAnn := ann[v1alpha1.AnnotationGatewayIssuer]
	if issuerAnn == "" {
		return ctrl.Result{}, nil
	}
	kind, name := parseIssuerAnnotation(issuerAnn)
	hosts, secretName := gatewayTLSTargets(gw)
	if secretName == "" || len(hosts) == 0 {
		return ctrl.Result{}, nil
	}
	cn := hosts[0]
	certName := fmt.Sprintf("gw-%s-%s", gw.GetName(), secretName)
	if len(certName) > 63 {
		certName = strings.TrimRight(certName[:63], "-")
	}
	desired := &v1alpha1.KNXVaultCertificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certName,
			Namespace: gw.GetNamespace(),
			Labels: map[string]string{
				"knxvault.kubenexis.dev/gateway": gw.GetName(),
			},
		},
		Spec: v1alpha1.KNXVaultCertificateSpec{
			SecretName:  secretName,
			IssuerRef:   v1alpha1.IssuerRef{Kind: kind, Name: name},
			CommonName:  cn,
			DNSNames:    hosts,
			Usages:      []string{"server auth"},
			Duration:    "2160h",
			RenewBefore: "720h",
		},
	}
	var existing v1alpha1.KNXVaultCertificate
	key := client.ObjectKey{Namespace: desired.Namespace, Name: certName}
	if err := r.Get(ctx, key, &existing); err != nil {
		if apierrors.IsNotFound(err) {
			if err := r.Create(ctx, desired); err != nil {
				return ctrl.Result{}, err
			}
			logger.Info("created certificate from gateway", "certificate", certName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	// Keep DNS names in sync
	existing.Spec.DNSNames = hosts
	existing.Spec.CommonName = cn
	existing.Spec.IssuerRef = desired.Spec.IssuerRef
	if err := r.Update(ctx, &existing); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers when Gateway API types exist; otherwise no-op watch.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if !r.Enabled {
		return nil
	}
	gw := &unstructured.Unstructured{}
	gw.SetGroupVersionKind(gatewayGVK)
	return ctrl.NewControllerManagedBy(mgr).
		For(gw).
		Complete(r)
}

// gatewayTLSTargets extracts hosts and first certificateRefs secret name from Gateway listeners.
func gatewayTLSTargets(gw *unstructured.Unstructured) (hosts []string, secretName string) {
	listeners, ok, _ := unstructured.NestedSlice(gw.Object, "spec", "listeners")
	if !ok {
		return nil, ""
	}
	seen := map[string]struct{}{}
	for _, raw := range listeners {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if h, _, _ := unstructured.NestedString(m, "hostname"); h != "" {
			if _, exists := seen[h]; !exists {
				seen[h] = struct{}{}
				hosts = append(hosts, h)
			}
		}
		// tls.certificateRefs[0].name
		tls, ok, _ := unstructured.NestedMap(m, "tls")
		if !ok {
			continue
		}
		refs, ok, _ := unstructured.NestedSlice(tls, "certificateRefs")
		if !ok || len(refs) == 0 {
			continue
		}
		ref, ok := refs[0].(map[string]any)
		if !ok {
			continue
		}
		if n, _, _ := unstructured.NestedString(ref, "name"); n != "" && secretName == "" {
			secretName = n
		}
	}
	return hosts, secretName
}
