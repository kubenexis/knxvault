<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Formal 3-cycle technical review — KNXVault

**Date:** 2026-07-16  
**Scope:** Full codebase review → remediate bugs → unit coverage gate ≥80% → docs  
**Baseline HEAD:** `cceb3cc` (prior 5-cycle security auditor)

## Executive summary

| | |
|--|--|
| **Coverage gate** | **Pass** (`make test-coverage` ≥80% pure operator + acme) |
| **Risk delta** | Several Medium bugs fixed (TTL abuse, backup JSON, HTTP-01 tokens, webhook mount, lockout memory) |
| **Deploy** | Unchanged: ship with existing production mitigations |

---

## Cycle 1 — Parsing, backup, token lifetime

| Finding | Severity | Remediation |
|---------|----------|-------------|
| `ParseTTL` accepted negative / zero / multi-century durations | Medium | Reject non-positive; cap at ~10y (`MaxParseTTL`) |
| `CreateToken` / renew could issue multi-year tokens | Medium | Clamp to `MaxClientTokenTTL` (30d) |
| Backup create ignored JSON bind errors | Medium | Parse body; invalid JSON → 400; empty → defaults |

## Cycle 2 — Challenge surface, webhook, DoS hygiene

| Finding | Severity | Remediation |
|---------|----------|-------------|
| HTTP-01 tokens with `/` or `..` accepted | Medium | `validateHTTP01Token` on Present + ServeHTTP |
| Webhook inject mount path `..` allowed | Medium | Absolute path without `..` required |
| Lockout maps unbounded under stuffing | Medium | Evict non-locked entries at 50k cap |
| Policy simulate nil auth panic | Low | Service-unavailable guard |

## Cycle 3 — Tests, coverage, documentation

- Unit tests for ParseTTL rejects, CreateToken clamp, HTTP-01 path tokens, webhook mount  
- `make test-coverage` + `go test ./...`  
- This report + security-model / testing notes  

## Residual

- Operator controller coverage remains outside pure-logic gate  
- Multi-share unseal still deferred  
- CSR IP SAN role constraints still open (W51-05)  

## Verify

```bash
make test
make test-coverage
go test ./... -count=1
```
