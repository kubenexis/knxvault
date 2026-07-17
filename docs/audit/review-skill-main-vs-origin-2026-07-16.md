<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

## Summary

This change set ships a substantial multi-issuer operator (Vault / ACME / SelfSigned), Vault product-profile routes (health, AppRole, custom-mount sign), and docs claiming cert-manager replacement readiness. Core Vault-mode issuance/renew and pure-logic packages look real; ACME HTTP-01, account-key persistence, Gateway RBAC, ClusterIssuer secret resolution, and CertificateRequest multi-issuer support are incomplete or broken relative to the docs/samples. Treat ACME and Gateway as non-production until the issues below are fixed.

## Issues

### Issue 1 -- Severity: bug
- File: internal/operator/manager.go:56-153
- Description: `Config.ACMEHTTP01Addr` / `KNXVAULT_ACME_HTTP01_ADDR` is loaded from env but never used. `Run()` never starts an HTTP listener and never mounts `MemoryHTTP01.ServeHTTP`. Docs, samples, and design claim HTTP-01 works via this env (`deployments/operator/samples/acme-clusterissuer-example.yaml:3`, `docs/design/multi-issuer-acme.md:43`).
- Suggestion: Construct a process-wide `MemoryHTTP01`, `go http.ListenAndServe(cfg.ACMEHTTP01Addr, presenter)` (or manager `Runnable`), and inject that same instance into ACME issue path. Fail fast or Ready=False when `http01: true` and addr unset.
- Status: open

### Issue 2 -- Severity: bug
- File: internal/acme/issuer_factory.go:25-26
- Description: Every `BuildSolvers` / `NewIssuerFromKind` call does `http01 = NewMemoryHTTP01()`, creating a throwaway store. Even if a listener existed, challenge tokens would be written to a different map than the one serving `/.well-known/acme-challenge/`. Operator path recreates this on every issue (`internal/operator/controllers/issuer_backend.go:77`).
- Suggestion: Accept a shared `HTTP01Presenter` (operator singleton) into `issueACME` / `NewIssuerFromKind`; only use per-call MemoryHTTP01 in unit tests.
- Status: open

### Issue 3 -- Severity: bug
- File: internal/operator/controllers/issuer_backend.go:54-77
- Description: `ACMEIssuerSpec.PrivateKeySecretRef` is defined (`internal/operator/apis/v1alpha1/types.go:103-104`) but never loaded/stored. `issueACME` always builds `acme.Config` without `AccountKey`, so `Client.Issue` generates a new ECDSA account key every reconcile (`internal/acme/client.go:123-130`). Breaks ACME account continuity, burns rate limits, and prevents recovery of existing LE accounts.
- Suggestion: Load PEM from Secret before Issue; if missing, generate, Register, Store back to Secret. For ClusterIssuer, resolve secret namespace explicitly (operator ns or `secretNamespace` field).
- Status: open

### Issue 4 -- Severity: bug
- File: internal/operator/controllers/issuer_backend.go:61
- Description: `AcceptTOS: true` is hardcoded. Config documents AcceptTOS as required user consent (`internal/acme/types.go:23-24`); CRD has no `acceptTOS` / `solvers` gate. Operator always agrees to CA ToS on behalf of the cluster.
- Suggestion: Add `spec.acme.acceptTOS` (bool, default false); refuse Ready/Issue when false; wire into `acme.Config.AcceptTOS`.
- Status: open

### Issue 5 -- Severity: bug
- File: internal/acme/webhook.go:20-47
- Description: DNS-01 `webhookURL` from CR is POSTed with no scheme/host allowlist, no block of link-local/metadata/loopback, and default `http.Client` (follows redirects). Any namespace that can create Issuer/ClusterIssuer can SSRF from the operator pod (cloud metadata, internal APIs). Same class of risk for attacker-controlled `spec.acme.server` via `ProbeDirectory` / ACME client (`internal/acme/client.go:89-114`, `245-250`) including `SkipTLSVerify`.
- Suggestion: Validate URL (https-only or explicit allowlist), deny private/link-local/metadata ranges, disable redirects, optional egress proxy policy. Restrict `SkipTLSVerify` to non-public directories (or env kill-switch).
- Status: open

### Issue 6 -- Severity: bug
- File: internal/operator/controllers/issuer_backend.go:69-75
- Description: Cloudflare/API token secrets always use `ns` = certificate namespace (`certificate_controller.go:143`). ClusterIssuer has no secret namespace; ClusterIssuer reconcile passes `ns=""` into `ensureIssuerReady` (`issuer_controller.go:80`) so CARef without explicit namespace resolves to empty namespace (`issuer_controller.go:133-136`). DNS-01 tokens and any future account-key Secret for ClusterIssuer are incorrectly scoped vs cert-manager (single Secret in controller ns).
- Suggestion: Add `ACMEIssuerSpec`/`ClusterIssuer` secret namespace (or operator default ns); use issuer namespace for namespaced Issuer secrets, not always cert ns; fix CARef default ns for ClusterIssuer to a documented default (e.g. `knxvault`).
- Status: open

### Issue 7 -- Severity: bug
- File: deployments/operator/rbac.yaml:29-31
- Description: RBAC grants `networking.k8s.io/ingresses` only. Gateway shim watches `gateway.networking.k8s.io/v1 Gateway` (`gateway_controller.go:20-25`, `107-116`) and is documented as supported (`docs/design/multi-issuer-acme.md:62`), but ClusterRole has no `gateways` rules. With `KNXVAULT_OPERATOR_GATEWAY_SHIM=true`, List/Watch/Get fail under least-privilege.
- Suggestion: Add `apiGroups: [gateway.networking.k8s.io] resources: [gateways] verbs: [get,list,watch]` (and document optional CRD install).
- Status: open

### Issue 8 -- Severity: bug
- File: internal/acme/client.go:225-242
- Description: `solve` calls Present for HTTP-01/DNS-01 but never CleanUp after Accept/WaitAuthorization (or on failure). Cloudflare TXT and webhook records accumulate; MemoryHTTP01 tokens linger if a shared store is ever fixed.
- Suggestion: `defer` CleanUp after Present (best-effort log on error); cleanup on authz failure paths too.
- Status: open

### Issue 9 -- Severity: bug
- File: internal/operator/controllers/resolve.go:46-57
- Description: `ResolveVaultRole` only reads legacy `Spec.VaultCAName`, not structured `spec.vault.vaultCAName`. CertificateRequest always uses this path (`certificaterequest_controller.go:44-50`) and never `ResolveIssuerFromRef` / ACME / SelfSigned. Issuers using only `spec.vault` fail CR path; ACME/SelfSigned CertificateRequests always fail.
- Suggestion: Use `ResolveIssuerFromRef` + mode switch (Vault SignCSR/Issue, ACME/SelfSigned only when CSR/issue shape allows); resolve VaultCA via `ResolvedIssuer.VaultCA`.
- Status: open

### Issue 10 -- Severity: bug
- File: internal/acme/selfsigned.go:62-103
- Description: `parseIPs(_ []string) []net.IP { return nil }` discards IPs; `OrderRequest` has no IP field; `IssueFromResolved` SelfSigned path never passes `ips` (`issuer_backend.go:33-38`). Certificate `spec.ipAddresses` silently omitted for SelfSigned (and ACME CSR also omits IPs in `client.go:183-186`).
- Suggestion: Add IPs to `OrderRequest`; implement `parseIPs`; include IP SANs in self-signed and ACME CSRs.
- Status: open

### Issue 11 -- Severity: suggestion
- File: internal/operator/controllers/certificate_controller.go:132-149
- Description: Renew (`Vault.Renew`) runs only for `IssuerModeVault` with existing serial/caId. ACME/SelfSigned always full re-issue (expected for ACME) but with broken account key + HTTP-01 this is worse than “no renew API.” Metrics count re-issues as Issues, not Renews. Fine once account key + solvers work; until then ACME renew window is a hard failure loop.
- Suggestion: Document explicitly; after account-key fix, treat ACME re-order as renew metric; surface distinct Ready condition when solver/account broken.
- Status: open

### Issue 12 -- Severity: suggestion
- File: internal/auth/approle.go:24-25
- Description: AppRole store is explicitly “not Raft-replicated yet.” Multi-node / restart loses `POST /sys/auth/approle` registrations; cert-manager AppRole login breaks after failover until re-register.
- Suggestion: Persist AppRoles via Raft/sys backend or document single-node-only + bootstrap hook; gate “Vault product profile” production claim.
- Status: open

### Issue 13 -- Severity: suggestion
- File: internal/operator/controllers/issuer_backend_test.go:1-53
- Description: Controller tests cover vault + self-signed only. No tests for: `issueACME` wiring (AcceptTOS, PrivateKeySecretRef, secret ns), HTTP-01 shared presenter, webhook URL validation, ClusterIssuer CARef empty ns, Gateway RBAC assumptions, CertificateRequest structured vault/ACME. Docs claim ACME LE HTTP-01 “Supported” without automated proof.
- Suggestion: Table-driven unit tests for secret ns + account key load/store; SSRF reject cases; integration test with pebble + shared HTTP-01 listener; demote support-matrix until green.
- Status: open

### Issue 14 -- Severity: nit
- File: docs/design/multi-issuer-acme.md:52-62
- Description: Support matrix marks ACME HTTP-01 and Gateway API as **Supported** while Issues 1–2 and 7 make those paths non-functional in-tree.
- Suggestion: Mark HTTP-01 / Gateway as Partial/Broken until fixed; align `certificate-support-matrix.md`.
- Status: open
