// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "fmt"

// ResolvedIssuer is a normalized multi-issuer configuration.
type ResolvedIssuer struct {
	Mode       string // Vault | ACME | SelfSigned
	VaultCA    string
	CARef      *IssuerRef
	ACME       *ACMEIssuerSpec
	SelfSigned *SelfSignedIssuerSpec
}

// ResolveIssuerSpec normalizes namespaced issuer fields.
func ResolveIssuerSpec(s KNXVaultIssuerSpec) (ResolvedIssuer, error) {
	return resolveMulti(s.VaultCAName, s.CARef, s.Vault, s.ACME, s.SelfSigned)
}

// ResolveClusterIssuerSpec normalizes cluster issuer fields.
func ResolveClusterIssuerSpec(s KNXVaultClusterIssuerSpec) (ResolvedIssuer, error) {
	return resolveMulti(s.VaultCAName, s.CARef, s.Vault, s.ACME, s.SelfSigned)
}

func resolveMulti(legacyCA string, legacyRef *IssuerRef, vault *VaultIssuerSpec, acme *ACMEIssuerSpec, self *SelfSignedIssuerSpec) (ResolvedIssuer, error) {
	n := 0
	if vault != nil {
		n++
	}
	if acme != nil {
		n++
	}
	if self != nil {
		n++
	}
	// Legacy vaultCAName counts as vault when no structured mode set.
	if n == 0 && legacyCA != "" {
		return ResolvedIssuer{Mode: IssuerModeVault, VaultCA: legacyCA, CARef: legacyRef}, nil
	}
	if n == 0 {
		return ResolvedIssuer{}, fmt.Errorf("issuer requires vault, acme, or selfSigned (or vaultCAName)")
	}
	if n > 1 {
		return ResolvedIssuer{}, fmt.Errorf("issuer must set exactly one of vault, acme, selfSigned")
	}
	switch {
	case vault != nil:
		ca := vault.VaultCAName
		if ca == "" {
			return ResolvedIssuer{}, fmt.Errorf("vault.vaultCAName required")
		}
		ref := vault.CARef
		if ref == nil {
			ref = legacyRef
		}
		return ResolvedIssuer{Mode: IssuerModeVault, VaultCA: ca, CARef: ref}, nil
	case acme != nil:
		return ResolvedIssuer{Mode: IssuerModeACME, ACME: acme}, nil
	default:
		return ResolvedIssuer{Mode: IssuerModeSelfSigned, SelfSigned: self}, nil
	}
}
