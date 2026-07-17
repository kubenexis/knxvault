<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security remediation — W81 High/Medium pack (2026-07-17)

Follow-up to the post-W80 full security audit.

## High / Medium remediations

| ID | Severity | Finding | Remediation |
|----|----------|---------|-------------|
| W81-01 | High | Intermediate `MaxPathLen: 0` without `MaxPathLenZero` | Set `MaxPathLenZero: true` + unit test |
| W81-02 | High | Unseal CIDR breadth still allowed `/8` | Production min prefix IPv4 `/16`, IPv6 `/48`; templates tightened |
| W81-03 | High | Webhook manifests missing TLS/caBundle | Deployment mounts `knxvault-webhook-tls`; mutating webhook requires `caBundle` |
| W81-04 | High | Lab profile / HTTP edge defaults | Coarse PKI off by default; operator/CSI/ESO https; doctor lab warn (prior) |
| W81-05 | High | HTTP vault URLs in edge deploy | Operator + CSI + ESO examples use `https://` |
| W81-06 | Medium | TokenReview no audiences | `KNXVAULT_K8S_TOKEN_AUDIENCES`; required in production when Raft enabled |
| W81-07 | Medium | Unseal defaulted to master key | Explicit `KNXVAULT_LAB_UNSEAL_EQUALS_MASTER` only; forbidden in production |
| W81-08 | Medium | Weak RSA `key_bits` | Floor 2048 in x509native |
| W81-09 | Medium | Vault-compat sign mount ACL bleed | Mount-scoped candidates only (`mount/*` not cross-`pki/*`) |
| W81-10 | Medium | Unbounded leaf TTL when role max 0 | Default max 90d on issue/sign + auto roles |
| W81-11 | Medium | Request signing optional | Documented residual defense-in-depth (not forced — client break) |
| W81-12 | Medium | Operator Secret clobber | Refuse update unless Secret owned by Certificate |
| W81-13 | Medium | CSI HTTP default | Default vaultAddr `https://` |
| W81-14 | Medium | SQL denylist gaps | Extra grant/security constructs denied |

## Residual (by design / deferred)

- Seal does not wipe master key from memory (API fence; HSM = M-CUSTODY-1).
- Auto-unseal KEK collocation (use external CSI/KMS for KEK).
- Soft multi-tenant, cleartext Raft metadata, non-PQ crypto.
- Request signing still optional (ops opt-in via `request_signing_required`).

## Verify

```bash
make quality
make clean all
```
