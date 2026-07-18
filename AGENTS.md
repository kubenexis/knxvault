<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# KNXVault — project instructions for humans and agents

These rules apply to **all** work in this repository (humans, Grok, other coding agents, subagents).  
**Non-negotiable principles below override convenience, demos, and “make it work faster.”**

Authoritative design: [`docs/design/distributed-trust-platform.md`](docs/design/distributed-trust-platform.md)  
Ops: [`docs/operations/instance-roles.md`](docs/operations/instance-roles.md) · Extensibility: [`docs/engineering/extensibility.md`](docs/engineering/extensibility.md) §9  
Contributing: [`docs/engineering/contributing.md`](docs/engineering/contributing.md)

---

## Mandatory agent behavior (Grok / AI assistants)

1. **Load and obey this file** at the start of any design, implementation, deploy, or security task.
2. **Before proposing or implementing** a change that touches deploy surface, auth methods, custody Secrets, operator RBAC, plugins, multi-tenant isolation, image packaging, or public ACME/OIDC:
   - Check the change against **N1–N5** and the **violation tripwires** below.
3. **If a user request, design, or your own draft would violate a principle:**
   - **Stop** before implementing the violating path.
   - **Immediately highlight** the issue in the first response section (or as soon as you detect it mid-task).
   - **Name the principle** (e.g. **N1**, **N3**).
   - **Elaborate**: what was proposed, why it breaks core security / DTP, blast radius, and a **compliant alternative**.
   - Do **not** silently implement a workaround that re-expands the custody TCB “just this once.”
4. **If the user explicitly insists** on a violation after the warning:
   - Re-state the risk clearly.
   - Require an **ADR** (and backlog note) before code that permanently weakens base defaults.
   - Prefer lab-only flags / separate demo overlays — never change production/base default surface without explicit product acceptance.
5. When reviewing PRs or diffs, **flag DTP principle regressions** as blocking (same severity as seal/crypto footguns) unless documented as intentional ADR.

---

## Non-negotiable principles (N1–N5)

### N1 — Core security over feature surface on the custody plane

Anything that holds **master key / unseal key / root bootstrap** is the **base** plane.

- **Must:** Keep airgap/core and default production installs **base-only** (Core + Kubernetes vault server).
- **Must not:** Enable public OIDC, public ACME/LE, CSI, ESO, or mutating webhook **by default** on the plane that holds custody material.
- **Must not:** Argue “it’s convenient for demos” as a reason to expand production/base kustomize.

### N2 — Instances over mega-vault

Hard isolation is by **instance and network**, not multi-tenant SaaS in one process (ADR-0011).

- **Must:** Prefer **core** vs **platform-edge** vs **public-TLS-edge** topologies for different trust needs.
- **Must not:** Build in-process multi-tenant SaaS isolation as a substitute for separate instances when custody blast radius is the concern.
- **Must:** Edge instances are **clients** of core with scoped policies — never copy master/unseal to edge.

### N3 — Add-ons are clients, not co-custodians

Operator, CSI, webhook, ESO (and similar) are **add-on services**.

- **Must:** Run as separate workloads/pods from the sealed vault process.
- **Must:** Use least-privilege credentials (K8s SA / AppRole / scoped token) — **never** long-lived root from the custody Secret in samples or production defaults.
- **Must not:** Grant operator (or other add-ons) blanket `get` on custody Secret `knxvault` (master/unseal/root).
- **Must not:** Co-locate public LE challenge plane with core custody when policy requires separation.

### N4 — Do not micro-split the sealed core

The sealed data plane (Raft + seal + envelope crypto + engines) is **one TCB**.

- **Must not:** Split auth / KV / PKI / ACME into microservices “for extensibility” without a formal ADR and threat model that justifies many new trust boundaries.
- **Must not:** Introduce a Vault-style in-process plugin (`.so` / shared memory) framework that loads untrusted code into the sealed process.
- **Must:** Prefer **versioned out-of-tree webhooks** (e.g. DNS-01) and **curated in-tree engines** (see extensibility §9).

### N5 — Default install stays base-only; gates fail closed

- **Must:** Default kustomize paths (`deployments/k8s/base`, `production`, `overlays/airgap-core`) deploy **vault only** — no CSI/ESO/webhook/ACME egress in the default surface.
- **Must:** Production/airgap feature gates keep OIDC/LDAP/audit-forward/ACME **off** unless an edge overlay explicitly enables them.
- **Must:** CI `make dtp-surface` (or equivalent) continues to guard base/production surface.
- **Must not:** Merge changes that re-add ACME egress or CSI/ESO/webhook into production/base without moving them under **components** and an explicit overlay.
- **Must not:** Bake `knxvault-cli` into the server container image (host/CI artifact only).

---

## Violation tripwires (detect and stop)

Treat any of the following as a **principle trip** — highlight immediately:

| Tripwire | Likely violates |
|----------|-----------------|
| Adding CSI/ESO/webhook/ACME resources to `deployments/k8s/base` or default `production` kustomization | N1, N5 |
| Operator Deployment binding `KNXVAULT_ROOT_TOKEN` / custody Secret for vault auth | N3 |
| Operator Role `get` on all Secrets in the vault namespace (including `knxvault`) | N3 |
| Enabling OIDC/LDAP/ACME by default in production/airgap ConfigMaps | N1, N5 |
| Proposal to split sealed core into microservices or load in-process plugins | N4 |
| Multi-tenant “soft isolation only” sold as hard isolation for regulated custody | N2 |
| Putting admin CLI into the distroless server image | N5 |
| Single mega-install guide that enables “all components” as the Day-0 path | N1, N5 |
| Edge copying master/unseal keys or using root for CSI/ESO | N2, N3 |
| Disabling `dtp-surface` / removing surface CI to land a feature | N5 |

### Response template when a trip is detected

```markdown
## Principle violation: N#

**Request / change:** …
**Why it trips N#:** …
**Blast radius:** (custody keys, audit surface, node agents, public internet, …)
**Compliant alternative:** …
**If you still want this:** requires ADR + explicit non-default overlay/lab flag; base defaults stay fail-closed.
```

---

## Capability growth (allowed patterns)

These improve capability **without** violating N1–N5:

| Goal | Compliant approach |
|------|-------------------|
| K8s secret injection | **platform-edge** overlay + CSI/webhook/ESO components; scoped SA to core |
| Public TLS (LE) | **public-TLS-edge** + operator ACME flag on; not on airgap-core |
| Federation (OIDC/LDAP) | Edge or dedicated instance; gates off on base |
| New secret engines | **In-tree** under existing seal/RBAC (curated) |
| DNS-01 providers | Out-of-tree **webhooks** + stable contract |
| Stronger custody | HSM / KMS auto-unseal on **base** (M-CUSTODY-1) |
| Smaller edge TCB | Optional thin images for CSI/webhook/ESO (same monorepo, version-locked) — still separate **pods** |

---

## Deploy surface quick reference

| Path | Surface |
|------|---------|
| `deployments/k8s/base` | Base only |
| `deployments/k8s/production` | Base + production profile |
| `deployments/k8s/overlays/airgap-core` | Base fail-closed |
| `deployments/k8s/overlays/platform-edge` | Base + CSI + webhook + ESO |
| `deployments/k8s/components/*` | Explicit add-ons only |

First-party images: **`knxvault`** (server + optional multi-binary commands) and **`knxvault-operator`**. CLI is not an image.

---

## Audit tagging

Tag findings and backlog items:

- `base` — custody, Raft, seal, KV, private PKI, server production deploy  
- `addon:operator` | `addon:csi` | `addon:eso` | `addon:webhook` | `addon:oidc` | `addon:acme`  

Do not report add-on-only risk as “core crypto is Critical” without scope clarity.

---

## Quality gates (do not weaken casually)

- `make quality` / `make all` before claiming done  
- Coverage gates for operator pure-logic and acme packages  
- `make dtp-surface` for base/production deploy surface  
- DCO sign-off, SPDX headers, license allowlist  

---

## Related docs

| Doc | Role |
|-----|------|
| [distributed-trust-platform.md](docs/design/distributed-trust-platform.md) | DTP design (Accepted) |
| [security-model.md](docs/architecture/security-model.md) | Threat model + audit taxonomy |
| [extensibility.md](docs/engineering/extensibility.md) | Plugins / split stance |
| [contributing.md](docs/engineering/contributing.md) | Human PR checklist including N1–N5 |
| [backlog.md](docs/backlog.md) | W90 / W86 tracking |
