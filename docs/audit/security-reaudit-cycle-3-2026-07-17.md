<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security re-audit — cycle 3 (2026-07-17)

Post-W83 formal re-audit.

## Verdict

**HOLD_NO_HM** — no Critical / High / Medium residual code issues identified beyond design residuals.

## Hygiene applied in this cycle

- Wrap `gcExpiredLocked` under mutex (map race).
- OCSP request body capped at 16 KiB (`MaxBytesReader`).

## Low / Info residual

- OCSP still unauthenticated crypto work (rate-limited + body cap).
- Transit multi-node rotate last-write-wins without CAS (requires transit write privilege).
- Design residuals: seal memory fence, HSM, soft multi-tenant, cleartext metadata, non-PQ.
