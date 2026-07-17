<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# PKI: native only (OpenSSL CLI backend removed)

KNXVault issues X.509 material with **in-process Go `crypto/x509` only**.

| Item | Status |
|------|--------|
| Native Go PKI | **Only** supported path |
| OpenSSL CLI backend | **Removed** |
| `KNXVAULT_PKI_BACKEND` | Unsupported (except the no-op value `native`) |
| `KNXVAULT_OPENSSL_BINARY` / `KNXVAULT_OPENSSL_TIMEOUT` | Unsupported — startup fails if set |

## Why

Production packaging is always multi-stage → `gcr.io/distroless/static-debian13:nonroot`. Distroless has no shell and no `/usr/bin/openssl`. Shipping a dual backend that required openssl on the host was a CrashLoop footgun and is no longer part of the product.

## Operator notes

- **Admin workstations** may still use the `openssl` CLI to generate random keys (`openssl rand -base64 32`). That is unrelated to knxvault’s PKI engine.
- **Certificates** issued by knxvault remain standard PEM X.509 (RSA SHA-256 today). Clients do not care that issuance is in-process.
- Historical ADR: [ADR-0002](../adr/0002-openssl-cli-crypto-backend.md) (superseded / removed).

## Related

- `Dockerfile` — distroless Debian 13 production image
- `internal/crypto/x509native/` — issuance implementation
- `internal/crypto/pki/native_backend.go` — PKI backend
