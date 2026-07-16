# Migration: cert-manager → KNXVault operator

See full guide: [`docs/operations/pki-replace-cert-manager.md`](../../../docs/operations/pki-replace-cert-manager.md).

## Quick mapping

| cert-manager | KNXVault |
|--------------|---------|
| `Issuer` / `ClusterIssuer` (Vault) | `KNXVaultIssuer` / `KNXVaultClusterIssuer` |
| `Certificate` | `KNXVaultCertificate` |
| `CertificateRequest` | `KNXVaultCertificateRequest` |
| `secretName` | same `spec.secretName` |
| `dnsNames` / `commonName` | same fields |
| `duration` / `renewBefore` | Go durations e.g. `2160h` / `720h` |

## Dual-run

1. Install operator CRDs + operator (pointed at same KNXVault).
2. Create matching `KNXVaultCertificate` with **same** `secretName` as cert-manager Certificate.
3. Scale down cert-manager Certificate (delete CR) once operator Secret is Ready.
4. Uninstall cert-manager when unused.
