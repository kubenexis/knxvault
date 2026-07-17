<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security re-audit — cycle 4 (2026-07-17)

## Finding fixed

| ID | Severity | Finding | Fix |
|----|----------|---------|-----|
| W85-01 | High | KVv2 could read cubbyhole/wrap/database/ssh/transit storage paths | `rejectReservedKVPath` on all KVv2 ops + list filter |

## Verdict after fix

High closed; design residuals unchanged.
