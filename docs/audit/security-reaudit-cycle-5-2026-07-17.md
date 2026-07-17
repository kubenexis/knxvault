<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security re-audit — cycle 5 final (2026-07-17)

## Verdict

**HOLD_NO_HM** — no Critical / High / Medium residual code issues after W81–W85.

## Verification

- W85 reserved KVv2 paths present and unit-tested.
- Empty-prefix list filters cubbyhole/internal paths.
- Wrap continues via `/sys/wrapping/*` only (not KV).

## Design residuals (accepted)

Seal memory fence, HSM/KMS, soft multi-tenant, cleartext Raft metadata, non-PQ crypto, optional request signing.

## Series summary

| Pack | Focus |
|------|--------|
| W81 | pathLen, unseal /16, audiences, RSA floor, mount sign, webhook TLS, … |
| W82 | SQL normalize/membership; ImportCA RSA |
| W83 | bare GRANT role; wrap CAS; ImportCA RSA-only |
| W84 | OCSP body cap; wrap GC mutex; HOLD hygiene |
| W85 | KVv2 internal path deny (High) |
