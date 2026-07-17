// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/metrics"
	"github.com/kubenexis/knxvault/internal/operator/statusutil"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

// CAReconciler reconciles KNXVaultCA.
type CAReconciler struct {
	client.Client
	Vault vaultiface.API
}

// Reconcile ensures a root or intermediate CA exists in vault.
func (r *CAReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	var ca v1alpha1.KNXVaultCA
	if err := r.Get(ctx, req.NamespacedName, &ca); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	vaultName := ca.Spec.VaultName
	if vaultName == "" {
		vaultName = ca.Name
	}
	// Idempotent: adopt existing vault CA by name.
	if existing, err := r.Vault.GetCAByName(ctx, vaultName); err == nil && existing != nil {
		ca.Status.CAID = existing.ID
		ca.Status.Serial = existing.Serial
		ca.Status.NotAfter = existing.ExpiresAt
		ca.Status.VaultName = vaultName
		ca.Status.Conditions = statusutil.ReadyTrue(ca.Status.Conditions, "Created", "CA already present in KNXVault")
		metrics.CAReady.Set(1)
		return ctrl.Result{}, r.Status().Update(ctx, &ca)
	}
	if ca.Status.CAID != "" && ca.Status.VaultName != "" {
		metrics.CAReady.Set(1)
		return ctrl.Result{}, nil
	}
	ttl := ca.Spec.TTL
	if ttl == "" {
		ttl = "87600h"
	}
	keyBits := ca.Spec.KeyBits
	typ := strings.ToLower(ca.Spec.Type)
	if typ == "" {
		typ = "root"
	}

	var (
		res *vaultiface.CAResult
		err error
	)
	switch typ {
	case "root":
		res, err = r.Vault.CreateRoot(ctx, vaultName, ca.Spec.CommonName, ttl, keyBits)
	case "intermediate":
		parent := ""
		if ca.Spec.ParentRef != nil {
			parent = ca.Spec.ParentRef.Name
			if ca.Spec.ParentRef.Namespace != "" || ca.Spec.ParentRef.Kind != "" {
				// Resolve parent CA CR vault name when possible.
				if p, rerr := ResolveVaultRole(ctx, r.Client, ca.Namespace, *ca.Spec.ParentRef); rerr == nil {
					parent = p
				}
			}
		}
		if parent == "" {
			err = fmt.Errorf("intermediate CA requires parentRef")
		} else {
			res, err = r.Vault.CreateIntermediate(ctx, parent, vaultName, ca.Spec.CommonName, ttl, keyBits)
		}
	default:
		err = fmt.Errorf("unsupported CA type %q", ca.Spec.Type)
	}

	if err != nil {
		// Adopt if name already exists in vault (idempotent create).
		if existing, e2 := r.Vault.GetCAByName(ctx, vaultName); e2 == nil && existing != nil {
			res = existing
			err = nil
		}
	}
	if err != nil {
		metrics.ErrorsTotal.WithLabelValues("ca").Inc()
		metrics.CAReady.Set(0)
		ca.Status.Conditions = statusutil.ReadyFalse(ca.Status.Conditions, "VaultError", err.Error())
		_ = r.Status().Update(ctx, &ca)
		logger.Error(err, "create CA")
		return ctrl.Result{}, err
	}

	ca.Status.CAID = res.ID
	ca.Status.Serial = res.Serial
	ca.Status.NotAfter = res.ExpiresAt
	ca.Status.VaultName = vaultName
	if res.Name != "" {
		ca.Status.VaultName = res.Name
	}
	ca.Status.Conditions = statusutil.ReadyTrue(ca.Status.Conditions, "Created", "CA provisioned in KNXVault")
	if err := r.Status().Update(ctx, &ca); err != nil {
		return ctrl.Result{}, err
	}
	metrics.CAReady.Set(1)
	logger.Info("CA ready", "caId", res.ID, "vaultName", ca.Status.VaultName)
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller.
func (r *CAReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KNXVaultCA{}).
		Complete(r)
}
