package controllers

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/reconcileutil"
	"github.com/kubenexis/knxvault/internal/operator/statusutil"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

// IssuerReconciler marks namespaced issuers Ready when vault CA exists.
type IssuerReconciler struct {
	client.Client
	Vault vaultiface.API
}

// Reconcile validates issuer against vault.
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var iss v1alpha1.KNXVaultIssuer
	if err := r.Get(ctx, req.NamespacedName, &iss); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if iss.Spec.VaultCAName == "" {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonInvalidSpec, "vaultCAName required")
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(1), nil
	}
	if err := ensureVaultCA(ctx, r.Vault, r.Client, iss.Namespace, iss.Spec.VaultCAName, iss.Spec.CARef); err != nil {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonPendingIssuer, err.Error())
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(2), nil
	}
	iss.Status.Conditions = statusutil.ReadyTrue(iss.Status.Conditions, reconcileutil.ReasonConfigured, "vault CA present")
	return ctrl.Result{}, r.Status().Update(ctx, &iss)
}

// SetupWithManager registers the controller.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultIssuer{}).
		Complete(r)
}

// ClusterIssuerReconciler marks cluster issuers Ready when vault CA exists.
type ClusterIssuerReconciler struct {
	client.Client
	Vault vaultiface.API
}

// Reconcile validates cluster issuer against vault.
func (r *ClusterIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var iss v1alpha1.KNXVaultClusterIssuer
	if err := r.Get(ctx, req.NamespacedName, &iss); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if iss.Spec.VaultCAName == "" {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonInvalidSpec, "vaultCAName required")
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(1), nil
	}
	if err := ensureVaultCA(ctx, r.Vault, r.Client, "", iss.Spec.VaultCAName, iss.Spec.CARef); err != nil {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonPendingIssuer, err.Error())
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(2), nil
	}
	iss.Status.Conditions = statusutil.ReadyTrue(iss.Status.Conditions, reconcileutil.ReasonConfigured, "vault CA present")
	return ctrl.Result{}, r.Status().Update(ctx, &iss)
}

// SetupWithManager registers the controller.
func (r *ClusterIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultClusterIssuer{}).
		Complete(r)
}

func ensureVaultCA(ctx context.Context, vault vaultiface.API, c client.Client, ns, vaultCAName string, ref *v1alpha1.IssuerRef) error {
	if vault == nil {
		return fmt.Errorf("vault client not configured")
	}
	// Prefer vault truth.
	if _, err := vault.GetCAByName(ctx, vaultCAName); err == nil {
		return nil
	}
	// Optional: CR Ready is a soft signal while CA is provisioning.
	if ref != nil && ref.Name != "" {
		var ca v1alpha1.KNXVaultCA
		key := client.ObjectKey{Name: ref.Name, Namespace: ref.Namespace}
		if key.Namespace == "" {
			key.Namespace = ns
		}
		if err := c.Get(ctx, key, &ca); err == nil {
			for _, cond := range ca.Status.Conditions {
				if cond.Type == v1alpha1.ConditionReady && cond.Status == "True" {
					// CR ready but vault lookup failed — still fail hard for issuer.
					break
				}
			}
		}
	}
	return fmt.Errorf("vault CA %q not found", vaultCAName)
}
