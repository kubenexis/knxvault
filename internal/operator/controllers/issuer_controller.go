package controllers

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/statusutil"
)

// IssuerReconciler marks namespaced issuers Ready when vaultCAName is set.
type IssuerReconciler struct {
	client.Client
}

// Reconcile validates issuer spec.
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var iss v1alpha1.KNXVaultIssuer
	if err := r.Get(ctx, req.NamespacedName, &iss); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if iss.Spec.VaultCAName == "" {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, "InvalidSpec", "vaultCAName required")
	} else {
		iss.Status.Conditions = statusutil.ReadyTrue(iss.Status.Conditions, "Configured", "Issuer ready")
	}
	return ctrl.Result{}, r.Status().Update(ctx, &iss)
}

// SetupWithManager registers the controller.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultIssuer{}).
		Complete(r)
}

// ClusterIssuerReconciler marks cluster issuers Ready.
type ClusterIssuerReconciler struct {
	client.Client
}

// Reconcile validates cluster issuer.
func (r *ClusterIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var iss v1alpha1.KNXVaultClusterIssuer
	if err := r.Get(ctx, req.NamespacedName, &iss); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if iss.Spec.VaultCAName == "" {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, "InvalidSpec", "vaultCAName required")
	} else {
		iss.Status.Conditions = statusutil.ReadyTrue(iss.Status.Conditions, "Configured", "ClusterIssuer ready")
	}
	return ctrl.Result{}, r.Status().Update(ctx, &iss)
}

// SetupWithManager registers the controller.
func (r *ClusterIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultClusterIssuer{}).
		Complete(r)
}
