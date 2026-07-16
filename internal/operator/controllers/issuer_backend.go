package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubenexis/knxvault/internal/acme"
	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

// IssueFromResolved issues a certificate using vault, ACME, or self-signed.
func IssueFromResolved(ctx context.Context, c client.Client, vault vaultiface.API, ns string, resolved v1alpha1.ResolvedIssuer, cn string, dns, ips []string, ttl string, keyBits int, clientUsage bool) (*vaultiface.CertResult, error) {
	switch resolved.Mode {
	case v1alpha1.IssuerModeVault:
		if vault == nil {
			return nil, fmt.Errorf("vault client not configured")
		}
		role := resolved.VaultCA
		return vault.Issue(ctx, role, cn, ttl, dns, ips, keyBits, clientUsage)
	case v1alpha1.IssuerModeSelfSigned:
		iss := &acme.SelfSignedIssuer{}
		if resolved.SelfSigned != nil && resolved.SelfSigned.TTL != "" {
			if d, err := time.ParseDuration(resolved.SelfSigned.TTL); err == nil {
				iss.DefaultTTL = d
			}
		}
		req := acme.OrderRequest{CommonName: cn, DNSNames: dns, IPAddresses: ips, KeyBits: keyBits}
		if ttl != "" {
			if d, err := time.ParseDuration(ttl); err == nil {
				req.TTL = d
			}
		}
		res, err := iss.Issue(ctx, req)
		if err != nil {
			return nil, err
		}
		return &vaultiface.CertResult{
			CertPEM: res.CertPEM, PrivateKeyPEM: res.PrivateKeyPEM,
			Serial: res.Serial, ExpiresAt: res.NotAfter.UTC().Format(time.RFC3339),
		}, nil
	case v1alpha1.IssuerModeACME:
		return issueACME(ctx, c, ns, resolved.ACME, cn, dns, ttl, keyBits)
	default:
		return nil, fmt.Errorf("unsupported issuer mode %q", resolved.Mode)
	}
}

func issueACME(ctx context.Context, c client.Client, ns string, spec *v1alpha1.ACMEIssuerSpec, cn string, dns []string, ttl string, keyBits int) (*vaultiface.CertResult, error) {
	if spec == nil {
		return nil, fmt.Errorf("acme spec required")
	}
	if !spec.AcceptTOS {
		return nil, fmt.Errorf("acme.acceptTOS must be true")
	}
	secretNS := ns
	if secretNS == "" {
		secretNS = spec.SecretNamespace
	}
	if secretNS == "" {
		secretNS = "knxvault"
	}
	cfg := acme.Config{
		DirectoryURL:  spec.Server,
		Email:         spec.Email,
		AcceptTOS:     spec.AcceptTOS,
		SkipTLSVerify: spec.SkipTLSVerify,
	}
	solvers := acme.SolverSpec{HTTP01: spec.HTTP01}
	if SharedHTTP01 != nil && spec.HTTP01 {
		// Prefer process-wide presenter when operator started HTTP-01 listener.
		// NewIssuerFromKind still builds MemoryHTTP01; we override after.
	}
	if spec.DNS01 != nil {
		solvers.DNSProvider = spec.DNS01.Provider
		solvers.WebhookURL = spec.DNS01.WebhookURL
		solvers.CloudflareZone = spec.DNS01.ZoneID
		if solvers.WebhookURL != "" {
			if err := acme.ValidateOutboundURL(solvers.WebhookURL); err != nil {
				return nil, fmt.Errorf("dns01.webhookURL: %w", err)
			}
		}
		if spec.DNS01.APITokenSecretRef != nil && c != nil {
			tok, err := readSecretKey(ctx, c, secretNS, spec.DNS01.APITokenSecretRef)
			if err != nil {
				return nil, err
			}
			solvers.CloudflareToken = tok
		}
	}
	iss, err := acme.NewIssuerFromKind("acme", cfg, solvers)
	if err != nil {
		return nil, err
	}
	// Wire shared HTTP-01 presenter (W50-07) so challenges hit the listening server.
	if cl, ok := iss.(*acme.Client); ok && SharedHTTP01 != nil && spec.HTTP01 {
		acme.SetHTTP01Presenter(cl, SharedHTTP01)
	}
	req := acme.OrderRequest{CommonName: cn, DNSNames: dns, KeyBits: keyBits}
	if ttl != "" {
		if d, err := time.ParseDuration(ttl); err == nil {
			req.TTL = d
		}
	}
	res, err := iss.Issue(ctx, req)
	if err != nil {
		return nil, err
	}
	return &vaultiface.CertResult{
		CertPEM: res.CertPEM, PrivateKeyPEM: res.PrivateKeyPEM,
		Serial: res.Serial, ExpiresAt: res.NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

func readSecretKey(ctx context.Context, c client.Client, ns string, ref *v1alpha1.SecretKeyRef) (string, error) {
	if ref == nil || ref.Name == "" {
		return "", fmt.Errorf("secret ref required")
	}
	key := ref.Key
	if key == "" {
		key = "api-token"
	}
	var sec corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &sec); err != nil {
		return "", err
	}
	b, ok := sec.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s missing key %q", ns, ref.Name, key)
	}
	return strings.TrimSpace(string(b)), nil
}

// ResolveIssuerFromRef loads Issuer/ClusterIssuer and returns resolved mode.
func ResolveIssuerFromRef(ctx context.Context, c client.Client, certNS string, ref v1alpha1.IssuerRef) (v1alpha1.ResolvedIssuer, error) {
	kind := strings.ToLower(ref.Kind)
	switch kind {
	case "", "knxvaultca", "ca":
		// Direct CA reference = vault mode with role = CA name
		role, err := ResolveVaultRole(ctx, c, certNS, ref)
		if err != nil {
			return v1alpha1.ResolvedIssuer{}, err
		}
		return v1alpha1.ResolvedIssuer{Mode: v1alpha1.IssuerModeVault, VaultCA: role}, nil
	case "knxvaultissuer", "issuer":
		ns := ref.Namespace
		if ns == "" {
			ns = certNS
		}
		var iss v1alpha1.KNXVaultIssuer
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &iss); err != nil {
			return v1alpha1.ResolvedIssuer{}, err
		}
		return v1alpha1.ResolveIssuerSpec(iss.Spec)
	case "knxvaultclusterissuer", "clusterissuer":
		var iss v1alpha1.KNXVaultClusterIssuer
		if err := c.Get(ctx, client.ObjectKey{Name: ref.Name}, &iss); err != nil {
			return v1alpha1.ResolvedIssuer{}, err
		}
		return v1alpha1.ResolveClusterIssuerSpec(iss.Spec)
	default:
		return v1alpha1.ResolvedIssuer{}, fmt.Errorf("unsupported issuer kind %q", ref.Kind)
	}
}
