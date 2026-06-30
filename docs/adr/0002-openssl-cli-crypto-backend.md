# ADR-0002: OpenSSL CLI as Cryptographic Backend

**Status:** Accepted  
**Date:** 2025

## Context

KNXVault must perform X.509 operations (root/intermediate CA creation, leaf issuance, CRL generation, OCSP) without implementing low-level cryptographic primitives in Go. Options included:

1. **Go `crypto/x509`** — native, no subprocess
2. **OpenSSL via CGO** — linked library, complex build
3. **OpenSSL CLI** — subprocess with sandboxed temp directories

## Decision

Use **OpenSSL 3.x CLI** via a sandboxed wrapper in `internal/crypto/openssl/`:

- Ephemeral `0700` temp directories per operation
- Strict argument validation; no user-controlled config paths
- Configurable binary path (`KNXVAULT_OPENSSL_BINARY`) and timeout
- Non-root container execution

Envelope encryption (AES-256-GCM for secrets and CA keys) uses Go `crypto` — only X.509 operations go through OpenSSL.

## Consequences

### Positive

- Auditable, well-understood cryptographic implementation
- No CGO build complexity
- Easy to swap OpenSSL builds or add engine support (Phase 4 HSM)
- Aligns with LLD security-first principle

### Negative

- Subprocess overhead on PKI operations
- Requires OpenSSL in container image and host PATH
- Sandbox escape is a residual risk (mitigated by validation and fuzzing)

### Follow-up

- Phase 4: OpenSSL engine abstraction for HSM
- Performance benchmarking under high issuance load
- Optional native `crypto/x509` fast path for read-only operations

## References

- [Security model](../architecture/security-model.md)
- `internal/crypto/openssl/wrapper.go`