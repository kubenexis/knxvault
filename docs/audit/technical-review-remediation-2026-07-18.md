<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Technical review remediation — 2026-07-18

**Branch:** `knxvault-distributed-trust-platform`  
**Scope:** Full technical review workflow after M-DTP + Phase A/B/C  
**Principles:** [`AGENTS.md`](../../AGENTS.md) N1–N5  

## Executive summary

| Field | Value |
|-------|--------|
| Overall residual risk (after pack) | **Medium** (open W86-10 shared rate limits, ABAC headers W86-12 design) |
| Critical open | **0** |
| High remediated this pack | ESO token race; operator Secret **write** isolation; ACME issue-time gate; CertificateRequest ownership |
| Medium remediated | ImportCA IsCA; SQL CTAS/PUBLIC; sqlite ban in strict/prod; production feature-gate fail-closed + edge override; operator leases namespaced; metrics NetPol sample; webhook empty volumes patch; unseal sample jump-only |
| Deploy recommendation | **Ship with mitigations** on base; enable add-ons only via platform-edge |

## Findings remediated

| Sev | ID | Fix |
|-----|-----|-----|
| High | ESO concurrent Token race | Per-request `client.New(addr, token)` |
| High | Operator SA update custody Secret | RBAC: create unrestricted; get/update/patch only named TLS/ACME Secrets |
| High | ACME still issues when disabled | CertificateReconciler `RejectACMEIfDisabled`; HTTP-01 only if ACMEEnabled |
| High | CertificateRequest Secret clobber | OwnerRef-only ownership (shared helper) |
| Med | W86-16 ImportCA leaf | Require IsCA + KeyUsageCertSign |
| Med | W86-15 SQL CTAS/PUBLIC | Deny list extended |
| Med | W86-17 sqlite/file admin | `AllowFileAdminURLs=false` under production/strict |
| Med | Production gates | Profile forces off; env re-applies for edge |
| Med | W86-19 leases | Namespaced Role |
| Med | W86-20 metrics | Sample NetPol |
| Med | Webhook volumes null | Full-array JSON patch when empty |
| Med | Unseal sample CIDR | Jump `/32` only |
| Low/Med | ESO error leak | Generic unauthorized / upstream messages |

## Residual (tracked, not fully closed)

| ID | Severity | Notes |
|----|----------|--------|
| W86-10 | Medium | Shared login/unseal rate limits (Valkey) |
| W86-11 | Medium | Request signing optional — doctor/docs only |
| W86-12 | Medium | Client ABAC headers — prefer claim binding (design) |
| W86-08 | Low/Med | Lab default profile — doctor warns non-loopback |

## Positive controls confirmed

DTP base surface, ESO TLS+auth defaults, Certificate OwnerRef, seal fail-closed, production ValidateSecurity, SSRF dial-time checks, operator no root token.

## Verification

```bash
make clean all
```

## Ops docs updated

- Base / platform-edge Day-0/Day-1  
- Operator security (write isolation + leases)  
- Configuration reference  
- This audit note  
