# PKI checklist — KNXVault security auditor

Use during any security or PKI-design review. Map findings to KNXVault packages.

## Hierarchy & key custody

- [ ] Root CA offline or tightly gated; intermediate used for day-to-day issuance
- [ ] CA private keys encrypted at rest (envelope / Raft encrypt-before-replicate)
- [ ] No CA key material in logs, metrics, audit details, or error messages
- [ ] Key ceremony / rotation procedure documented (`docs/operations/`)
- [ ] Compromise runbook exists (CA compromise, re-issue, CRL)

## Certificate profiles

- [ ] Server TLS: digitalSignature + keyEncipherment/ECDH, serverAuth EKU
- [ ] Client TLS: clientAuth EKU; no serverAuth unless intended
- [ ] TTL defaults short for leaves; max TTL enforced server-side
- [ ] SANs validated (DNS, IP); CN injection blocked (OpenSSL DN)
- [ ] Path length constraints on intermediates where design requires

## Issuance paths (KNXVault)

| Path | Package | Checks |
|------|---------|--------|
| Native issue / renew | `internal/engine/pki`, handlers | AuthZ `pki` write; role policy; TTL clamp |
| CSR sign | PKI service + vaultcompat | CSR fields vs role; no unrestricted CA use |
| Vault-compat `/v1/.../sign/:role` | `internal/api/handlers/vaultcompat.go` | Path-scoped capability; token required |
| Operator multi-issuer | `internal/operator` | Vault / ACME / SelfSigned isolation |
| ACME | `internal/acme` | AcceptTOS; SSRF; account key Secret; HTTP-01/DNS-01 safety |
| Self-signed | `internal/acme/selfsigned.go` | Lab-only framing in docs |

## ACME-specific

- [ ] `acceptTOS` required before Issue
- [ ] Outbound webhook/directory URL SSRF-safe (no RFC1918/metadata)
- [ ] `skipTLSVerify` forbidden for public Let’s Encrypt hosts
- [ ] Account key load/store via `privateKeySecretRef` (stable LE account)
- [ ] Challenge cleanup after success/failure
- [ ] HTTP-01 presenter not exposing other secrets

## Revocation & status

- [ ] Revoke requires authZ; audited
- [ ] CRL distribution available and integrity-protected as designed
- [ ] OCSP path does not leak key material; signer key memzero’d after use

## Kubernetes trust consumers

- [ ] CSI provider: socket perms, SA login, object mode 0400 files
- [ ] Webhook: TLS required for admission
- [ ] Operator: least-privilege RBAC (TokenReview, secrets, gateway/ingress as needed)
- [ ] Cert Secrets not cluster-wide readable
- [ ] NetworkPolicy limits who can hit vault API and metrics

## Common PKI anti-patterns (flag aggressively)

- Long-lived leaves (years) without business justification
- Shared intermediate private key across environments
- AuthZ that treats all of `pki` as a single blob without role/mount scope
- Exporting private keys over API without sudo + audit
- Disabling seal / using insecure K8s auth with Raft in “prod” profiles
