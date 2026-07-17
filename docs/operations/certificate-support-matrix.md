# Certificate automation support matrix

What KNXVault covers **without cert-manager**, and what remains external.

## Claim

**KNXVault replaces cert-manager for private CA, self-signed, and ACME (public) certificate automation in Kubernetes** when using **knxvault-operator** multi-issuer CRDs.

You do **not** need the cert-manager controller for:

- Vault-issued TLS (roots / intermediates in KNXVault)
- Self-signed leaves
- ACME (Let's Encrypt and other RFC 8555 CAs) with HTTP-01 or DNS-01

## Matrix

| Use case | Supported | How |
|----------|-----------|-----|
| Private CA leaf → TLS Secret | Yes | `issuerRef` → Vault mode ClusterIssuer / CA |
| Intermediate hierarchy | Yes | `KNXVaultCA` root + intermediate |
| CSR sign | Yes | `KNXVaultCertificateRequest` + `POST /pki/sign` |
| Renew before expiry | Yes | Operator `renewBefore` (vault renew when caId set) |
| Self-signed | Yes | `spec.selfSigned` on Issuer |
| ACME HTTP-01 (Kubernetes) | Yes | Operator `spec.acme.http01: true` + reachable solver |
| ACME DNS-01 Cloudflare (Kubernetes) | Yes | Operator `spec.acme.dns01.provider: cloudflare` |
| ACME DNS-01 custom DNS (Kubernetes) | Yes | Operator `provider: webhook` |
| ACME / Let's Encrypt (standalone + CLI) | **Yes (M-ACME-1)** | Host `knxvault-cli acme` + `internal/acme` — [unified ACME design](../design/acme-letsencrypt-unified.md); profile examples under `examples/acme/` |
| Ingress annotation | Yes | `knxvault.kubenexis.dev/issuer` + ingress shim env |
| Gateway API annotation | Yes | Same annotation + gateway shim env |
| cert-manager YAML migration | Yes | `cmcompat` conversion helpers / dual-run map |
| Venafi / cloud public CA APIs | No | Use external tooling or future plugin |
| Live dual-serve `cert-manager.io` CRDs | No | Convert to knxvault CRDs instead |

## Prefer operator over Vault profile

| Path | When |
|------|------|
| **Operator CRDs** | New clusters; no cert-manager install |
| **Vault product profile `/v1/*`** | Temporary dual-run while cert-manager still installed |

## Samples

- Vault: `deployments/operator/samples/certificate-example.yaml`
- Self-signed: `deployments/operator/samples/selfsigned-certificate.yaml`
- ACME: `deployments/operator/samples/acme-clusterissuer-example.yaml`

## See also

- [Replace cert-manager](pki-replace-cert-manager.md)
- [Multi-issuer ACME design](../design/multi-issuer-acme.md)
- [cert-manager Vault profile recipe](../recipes/cert-manager-integration.md)
