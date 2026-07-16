# Golang security checklist — KNXVault

## Cryptography

- [ ] Only `crypto/rand` for keys/nonces (never `math/rand`)
- [ ] AES-GCM (or approved AEAD) for envelope; no ECB/CBC-without-HMAC
- [ ] Secret compares: `subtle.ConstantTimeCompare` with **equal-length** inputs or hash-then-compare
- [ ] DEK/key material zeroed after use on Seal/Open/Reencrypt/PKI CA load paths (`memzero`)
- [ ] TLS min version 1.2+; cipher suites not weakened
- [ ] `InsecureSkipVerify` only behind explicit lab config and blocked for public CAs

## Authentication & authorization

- [ ] Middleware fail-closed if auth service nil
- [ ] Every mutating and secret-read route behind Auth + capability check
- [ ] Agent tokens: action allow-list + path prefix enforced
- [ ] RBAC sync failure: fail-closed when production flag set
- [ ] Lockout / rate limit on login and unseal
- [ ] Root/bootstrap token short TTL; not embedded in images

## Input validation

- [ ] KV paths reject `..` and are cleaned (path param **and** query prefix)
- [ ] Hostnames / CNs reject DN injection (`/`, nulls)
- [ ] URLs for webhooks/ACME: scheme allow-list + private IP block (SSRF)
- [ ] Managed SQL: statement allow-list; no stacked queries
- [ ] JSON binding size / type safety on privileged endpoints

## HTTP surface

- [ ] Timeouts on server and outbound clients
- [ ] No open redirects; no following redirects to private IPs on webhooks
- [ ] Metrics unauthenticated only with network isolation or bearer token
- [ ] Seal guard: exact allow paths only (no suffix tricks)
- [ ] Request signing / exposure HMAC includes timestamp + skew when used

## Concurrency & DoS

- [ ] Shared maps (rate limit, lockout, exposure seen-set) bounded or TTL-evicted
- [ ] Audit forwarder: bounded queue, drop metrics, no unbounded goroutine-per-event
- [ ] Context cancellation on outbound calls
- [ ] Raft / leader paths don’t block forever without timeout

## Secrets & logging

- [ ] No passwords, tokens, PEMs in zap/slog fields or audit `details` (sanitize)
- [ ] Error messages don’t echo secrets
- [ ] Config files not world-readable when containing secrets

## Supply chain & build

- [ ] Direct deps permissive licenses (project policy)
- [ ] `govulncheck` / trivy clean for Critical/High when gate required
- [ ] Non-root containers; minimal base images
- [ ] SBOM generated in release pipeline when available

## Testing expectations for security fixes

- [ ] Unit test for the failure mode (bypass attempt returns 4xx/5xx)
- [ ] Regression test named or commented with backlog ID when applicable
- [ ] `make test-coverage` still meets gate after changes
