// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubenexis/knxvault/internal/acme"
	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/reconcileutil"
	"github.com/kubenexis/knxvault/internal/operator/statusutil"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

// IssuerReconciler marks namespaced issuers Ready when backend is available.
type IssuerReconciler struct {
	client.Client
	Vault vaultiface.API
	// ACMEEnabled when false rejects ACME issuer types (M-DTP-2 / W90-22).
	ACMEEnabled bool
}

// Reconcile validates issuer against vault / ACME directory / self-signed.
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var iss v1alpha1.KNXVaultIssuer
	if err := r.Get(ctx, req.NamespacedName, &iss); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	resolved, err := v1alpha1.ResolveIssuerSpec(iss.Spec)
	if err != nil {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonInvalidSpec, err.Error())
		iss.Status.Mode = ""
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(1), nil
	}
	if resolved.Mode == v1alpha1.IssuerModeACME && !r.ACMEEnabled {
		msg := "ACME issuers disabled (set KNXVAULT_OPERATOR_ACME_ENABLED=true for public LE)"
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonInvalidSpec, msg)
		iss.Status.Mode = resolved.Mode
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(1), nil
	}
	if err := ensureIssuerReady(ctx, r.Vault, r.Client, iss.Namespace, resolved); err != nil {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonPendingIssuer, err.Error())
		iss.Status.Mode = resolved.Mode
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(2), nil
	}
	iss.Status.Mode = resolved.Mode
	iss.Status.Conditions = statusutil.ReadyTrue(iss.Status.Conditions, reconcileutil.ReasonConfigured, "issuer ready")
	return ctrl.Result{}, r.Status().Update(ctx, &iss)
}

// SetupWithManager registers the controller.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultIssuer{}).
		Complete(r)
}

// ClusterIssuerReconciler marks cluster issuers Ready when backend is available.
type ClusterIssuerReconciler struct {
	client.Client
	Vault vaultiface.API
	// ACMEEnabled when false rejects ACME issuer types (M-DTP-2 / W90-22).
	ACMEEnabled bool
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
	resolved, err := v1alpha1.ResolveClusterIssuerSpec(iss.Spec)
	if err != nil {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonInvalidSpec, err.Error())
		iss.Status.Mode = ""
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(1), nil
	}
	if resolved.Mode == v1alpha1.IssuerModeACME && !r.ACMEEnabled {
		msg := "ACME issuers disabled (set KNXVAULT_OPERATOR_ACME_ENABLED=true for public LE)"
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonInvalidSpec, msg)
		iss.Status.Mode = resolved.Mode
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(1), nil
	}
	if err := ensureIssuerReady(ctx, r.Vault, r.Client, "", resolved); err != nil {
		iss.Status.Conditions = statusutil.ReadyFalse(iss.Status.Conditions, reconcileutil.ReasonPendingIssuer, err.Error())
		iss.Status.Mode = resolved.Mode
		_ = r.Status().Update(ctx, &iss)
		return reconcileutil.ErrorResult(2), nil
	}
	iss.Status.Mode = resolved.Mode
	iss.Status.Conditions = statusutil.ReadyTrue(iss.Status.Conditions, reconcileutil.ReasonConfigured, "issuer ready")
	return ctrl.Result{}, r.Status().Update(ctx, &iss)
}

// SetupWithManager registers the controller.
func (r *ClusterIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultClusterIssuer{}).
		Complete(r)
}

func ensureIssuerReady(ctx context.Context, vault vaultiface.API, c client.Client, ns string, resolved v1alpha1.ResolvedIssuer) error {
	switch resolved.Mode {
	case v1alpha1.IssuerModeVault:
		return ensureVaultCA(ctx, vault, c, ns, resolved.VaultCA, resolved.CARef)
	case v1alpha1.IssuerModeSelfSigned:
		return nil
	case v1alpha1.IssuerModeACME:
		if resolved.ACME == nil {
			return fmt.Errorf("acme config required")
		}
		if !resolved.ACME.AcceptTOS {
			return fmt.Errorf("acme.acceptTOS must be true")
		}
		if !resolved.ACME.HTTP01 && resolved.ACME.DNS01 == nil {
			return fmt.Errorf("acme issuer requires http01 and/or dns01")
		}
		// Directory probe when server set (skip for empty = will use LE default at issue time).
		cfg := acme.Config{DirectoryURL: resolved.ACME.Server, SkipTLSVerify: resolved.ACME.SkipTLSVerify}
		cli := acme.NewClient(cfg, nil, nil)
		info := cli.ProbeDirectory(ctx)
		if resolved.ACME.Server != "" && !info.Ready {
			return fmt.Errorf("acme directory: %s", info.Message)
		}
		return nil
	default:
		return fmt.Errorf("unknown mode %s", resolved.Mode)
	}
}

func ensureVaultCA(ctx context.Context, vault vaultiface.API, c client.Client, ns, vaultCAName string, ref *v1alpha1.IssuerRef) error {
	if vault == nil {
		return fmt.Errorf("vault client not configured")
	}
	if _, err := vault.GetCAByName(ctx, vaultCAName); err == nil {
		return nil
	}
	if ref != nil && ref.Name != "" {
		var ca v1alpha1.KNXVaultCA
		key := client.ObjectKey{Name: ref.Name, Namespace: ref.Namespace}
		if key.Namespace == "" {
			key.Namespace = ns
		}
		if err := c.Get(ctx, key, &ca); err == nil {
			for _, cond := range ca.Status.Conditions {
				if cond.Type == v1alpha1.ConditionReady && cond.Status == "True" {
					return nil
				}
			}
			return fmt.Errorf("CA %s not Ready yet", ref.Name)
		}
	}
	return fmt.Errorf("vault CA %q not found", vaultCAName)
}
