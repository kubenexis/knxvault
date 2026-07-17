// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
)

// ResolveVaultRole maps issuerRef to the vault CA name used as issue role.
func ResolveVaultRole(ctx context.Context, c client.Client, certNS string, ref v1alpha1.IssuerRef) (role string, err error) {
	kind := strings.ToLower(ref.Kind)
	switch kind {
	case "", "knxvaultca", "ca":
		ns := ref.Namespace
		if ns == "" {
			ns = certNS
		}
		var ca v1alpha1.KNXVaultCA
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &ca); err != nil {
			// Fall back: treat Name as vault CA name (bootstrap without waiting for CR status).
			if ref.Name != "" {
				return ref.Name, nil
			}
			return "", err
		}
		if ca.Status.VaultName != "" {
			return ca.Status.VaultName, nil
		}
		if ca.Spec.VaultName != "" {
			return ca.Spec.VaultName, nil
		}
		return ca.Name, nil
	case "knxvaultissuer", "issuer":
		ns := ref.Namespace
		if ns == "" {
			ns = certNS
		}
		var iss v1alpha1.KNXVaultIssuer
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &iss); err != nil {
			return "", err
		}
		resolved, err := v1alpha1.ResolveIssuerSpec(iss.Spec)
		if err != nil {
			return "", err
		}
		if resolved.Mode != v1alpha1.IssuerModeVault || resolved.VaultCA == "" {
			return "", fmt.Errorf("issuer %s/%s is not vault mode", ns, ref.Name)
		}
		return resolved.VaultCA, nil
	case "knxvaultclusterissuer", "clusterissuer":
		var iss v1alpha1.KNXVaultClusterIssuer
		if err := c.Get(ctx, client.ObjectKey{Name: ref.Name}, &iss); err != nil {
			return "", err
		}
		resolved, err := v1alpha1.ResolveClusterIssuerSpec(iss.Spec)
		if err != nil {
			return "", err
		}
		if resolved.Mode != v1alpha1.IssuerModeVault || resolved.VaultCA == "" {
			return "", fmt.Errorf("clusterissuer %s is not vault mode", ref.Name)
		}
		return resolved.VaultCA, nil
	default:
		return "", fmt.Errorf("unsupported issuer kind %q", ref.Kind)
	}
}
