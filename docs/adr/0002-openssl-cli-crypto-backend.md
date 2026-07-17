# ADR-0002: OpenSSL CLI as Cryptographic Backend

**Status:** Superseded / removed  
**Date:** 2025  
**Updated:** 2026-07

## Context

KNXVault originally performed X.509 operations via the OpenSSL 3.x CLI in a sandboxed temp directory (no CGO). A later native Go `crypto/x509` backend was added for distroless images.

## Decision (original)

Use OpenSSL CLI for PKI issuance; envelope encryption stayed in Go.

## Decision (current)

**Remove the OpenSSL CLI PKI backend entirely.** knxvault is always packaged as `gcr.io/distroless/static-debian13:nonroot` and always issues certificates with Go `crypto/x509` (`internal/crypto/x509native`, `internal/crypto/pki.NativeBackend`).

Config knobs `KNXVAULT_PKI_BACKEND`, `KNXVAULT_OPENSSL_BINARY`, and `KNXVAULT_OPENSSL_TIMEOUT` are rejected at load time if set to OpenSSL-related values.

## Consequences

- No openssl binary required at runtime
- No subprocess / sandbox escape residual risk for PKI
- No dual-backend operator confusion or CrashLoop when openssl is missing
- Future PQ / exotic algorithms land in Go (or a new in-process provider), not via CLI

## References

- [PKI native only](../operations/pki-openssl-migration.md)
- `internal/crypto/x509native/`
