// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package cmcompat maps cert-manager-shaped Certificate/Issuer fields onto
// KNXVault CRDs for migration (drop-in YAML conversion without running cert-manager).
package cmcompat

import (
	"fmt"
	"strings"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
)

// CMCertificate is a minimal cert-manager Certificate.spec subset.
type CMCertificate struct {
	SecretName  string
	CommonName  string
	DNSNames    []string
	IPAddresses []string
	Duration    string
	RenewBefore string
	IssuerRef   CMIssuerRef
	Usages      []string
}

// CMIssuerRef is cert-manager issuerRef.
type CMIssuerRef struct {
	Name  string
	Kind  string
	Group string
}

// CMIssuer is a minimal cert-manager Issuer/ClusterIssuer.spec subset.
type CMIssuer struct {
	// Type is vault | acme | selfSigned | ca (ca maps to vault CA name).
	Type string
	// Vault CA name when Type=vault or ca.
	VaultCAName string
	// ACME directory / email / http01.
	ACMEServer string
	ACMEEmail  string
	HTTP01     bool
	// DNS01 provider: webhook | cloudflare | memory
	DNS01Provider   string
	DNS01WebhookURL string
	SelfSigned      bool
}

// ConvertCertificate maps a cert-manager Certificate to KNXVaultCertificateSpec.
func ConvertCertificate(in CMCertificate) (v1alpha1.KNXVaultCertificateSpec, error) {
	if in.SecretName == "" {
		return v1alpha1.KNXVaultCertificateSpec{}, fmt.Errorf("secretName required")
	}
	cn := in.CommonName
	if cn == "" && len(in.DNSNames) > 0 {
		cn = in.DNSNames[0]
	}
	if cn == "" {
		return v1alpha1.KNXVaultCertificateSpec{}, fmt.Errorf("commonName or dnsNames required")
	}
	kind := mapIssuerKind(in.IssuerRef.Kind, in.IssuerRef.Group)
	return v1alpha1.KNXVaultCertificateSpec{
		SecretName:  in.SecretName,
		CommonName:  cn,
		DNSNames:    in.DNSNames,
		IPAddresses: in.IPAddresses,
		Duration:    in.Duration,
		RenewBefore: in.RenewBefore,
		Usages:      in.Usages,
		IssuerRef: v1alpha1.IssuerRef{
			Kind: kind,
			Name: in.IssuerRef.Name,
		},
		Delivery: v1alpha1.DeliverySecret,
	}, nil
}

func mapIssuerKind(kind, group string) string {
	k := strings.ToLower(kind)
	switch k {
	case "clusterissuer":
		return "KNXVaultClusterIssuer"
	case "issuer":
		return "KNXVaultIssuer"
	case "knxvaultclusterissuer", "knxvaultissuer", "knxvaultca":
		return kind
	default:
		if strings.Contains(strings.ToLower(group), "cert-manager") {
			if k == "clusterissuer" {
				return "KNXVaultClusterIssuer"
			}
			return "KNXVaultIssuer"
		}
		if kind == "" {
			return "KNXVaultClusterIssuer"
		}
		return kind
	}
}

// ConvertIssuer maps cert-manager Issuer config to KNXVaultIssuerSpec.
func ConvertIssuer(in CMIssuer) (v1alpha1.KNXVaultIssuerSpec, error) {
	t := strings.ToLower(in.Type)
	switch {
	case in.SelfSigned || t == "selfsigned":
		return v1alpha1.KNXVaultIssuerSpec{SelfSigned: &v1alpha1.SelfSignedIssuerSpec{}}, nil
	case t == "acme":
		spec := &v1alpha1.ACMEIssuerSpec{
			Server: in.ACMEServer,
			Email:  in.ACMEEmail,
			HTTP01: in.HTTP01,
		}
		if in.DNS01Provider != "" {
			spec.DNS01 = &v1alpha1.ACMEDNS01Spec{
				Provider:   in.DNS01Provider,
				WebhookURL: in.DNS01WebhookURL,
			}
		}
		if !spec.HTTP01 && spec.DNS01 == nil {
			spec.HTTP01 = true
		}
		return v1alpha1.KNXVaultIssuerSpec{ACME: spec}, nil
	case t == "vault" || t == "ca" || t == "":
		if in.VaultCAName == "" {
			return v1alpha1.KNXVaultIssuerSpec{}, fmt.Errorf("vaultCAName required for vault/ca issuer")
		}
		return v1alpha1.KNXVaultIssuerSpec{
			Vault: &v1alpha1.VaultIssuerSpec{VaultCAName: in.VaultCAName},
		}, nil
	default:
		return v1alpha1.KNXVaultIssuerSpec{}, fmt.Errorf("unsupported cert-manager issuer type %q", in.Type)
	}
}

// ConvertClusterIssuer same as ConvertIssuer but for cluster scope.
func ConvertClusterIssuer(in CMIssuer) (v1alpha1.KNXVaultClusterIssuerSpec, error) {
	ns, err := ConvertIssuer(in)
	if err != nil {
		return v1alpha1.KNXVaultClusterIssuerSpec{}, err
	}
	return v1alpha1.KNXVaultClusterIssuerSpec(ns), nil
}
