# PKI OpenSSL to Native Backend Migration

KNXVault supports two PKI issuance backends:

| Backend | Config | OpenSSL required |
|---------|--------|------------------|
| `openssl` (default) | `KNXVAULT_PKI_BACKEND=openssl` | Yes |
| `native` | `KNXVAULT_PKI_BACKEND=native` | No |

The native backend uses Go `crypto/x509` for root, intermediate, and leaf issuance (RSA SHA-256). CRL generation and OCSP verification already use native code paths.

## When to migrate

- Distroless or minimal container images without OpenSSL
- Environments that restrict subprocess execution
- Standard RSA SHA-256 PKI with DNS SAN leaf certificates

## Migration steps

1. **Validate in staging** with `KNXVAULT_PKI_BACKEND=native`.
2. **Run doctor** — a warning (not failure) appears if OpenSSL is missing while native is enabled:
   ```bash
   KNXVAULT_PKI_BACKEND=native knxvault-cli doctor --addr https://vault.example:8200
   ```
3. **Issue test certificates** (root, intermediate, leaf with SAN) and verify chains.
4. **Deploy** using `Dockerfile.distroless` or set the env var on your existing deployment.
5. **Monitor** PKI metrics and audit logs for issuance errors.

## Rollback

Set `KNXVAULT_PKI_BACKEND=openssl` (or unset the variable). OpenSSL must be available on the host or in the container image.

## Limitations

The native backend currently targets RSA keys with SHA-256 signatures. Exotic key types (ECDSA P-384, Ed25519) may still require the OpenSSL backend until parity is extended.

## Related

- [ADR-0002: OpenSSL CLI crypto backend](../adr/0002-openssl-cli-crypto-backend.md)
- `internal/crypto/pki/backend.go` — backend interface
- `internal/crypto/x509native/` — native implementation