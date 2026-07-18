<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Base instance Day-0 / Day-1 (core / airgap)

**Audience:** Operators bringing up a **custody** instance (master/unseal, critical KV, private CA).  
**Principles:** [`AGENTS.md`](../../AGENTS.md) **N1–N5** · [instance-roles.md](instance-roles.md) · [airgap-checklist.md](airgap-checklist.md)

This path deploys **base only** — no CSI, ESO, webhook, or public ACME/OIDC.

---

## Day-0 — Bring-up

### 0.1 Images and CLI

| Artifact | Required |
|----------|----------|
| `ghcr.io/kubenexis/knxvault` | Yes |
| Host `knxvault-cli` | Yes |
| `knxvault-operator` | No (optional private CRDs later) |

```bash
make container-build build-cli
# airgap: make container-export
```

### 0.2 Secrets (custody)

Edit or create Secret `knxvault` (label `knxvault.kubenexis.dev/custody=true`):

- Distinct `KNXVAULT_MASTER_KEY` and `KNXVAULT_UNSEAL_KEY`
- Short-lived `KNXVAULT_ROOT_TOKEN`
- Production: `KNXVAULT_AUDIT_SIGNING_KEY`, `KNXVAULT_METRICS_BEARER_TOKEN`
- Raft mTLS Secret `knxvault-raft-tls` (multi-node production)

### 0.3 Unseal plane (W86-09)

Production ConfigMap uses **admin jump `/32` only** (not pod `/24` — api-client pods must not reach unseal).

Unseal traffic: only namespaces labeled `knxvault.kubenexis.dev/unseal-client=true` (NetworkPolicy).  
**Do not** expose `/sys/unseal` on public Ingress (see `deployments/k8s/production/ingress-api-no-unseal.yaml`, W86-14).

### 0.4 Apply base

```bash
# Lab base
kubectl apply -k deployments/k8s/base

# Production base (profile + metrics + Raft mTLS mounts + gates off)
kubectl apply -k deployments/k8s/production

# Airgap core (gates forced off)
kubectl apply -k deployments/k8s/overlays/airgap-core
```

Verify surface:

```bash
make dtp-surface
kubectl kustomize deployments/k8s/production | grep -Ei 'csi|eso|webhook|acme' && echo FAIL || echo OK
```

### 0.5 Unseal and doctor

From admin jump (unseal-client label):

```bash
export KNXVAULT_ADDR=https://knxvault.example.com
export KNXVAULT_TOKEN=<bootstrap-root>
# Unseal via ClusterIP/path not on public Ingress — see seal-and-unseal recipe
knxvault-cli doctor --profile production \
  --feature-oidc=false --feature-ldap=false \
  --feature-audit-forward=false --feature-acme=false
```

### 0.6 Feature gates (must stay false on base)

| Variable | Value |
|----------|--------|
| `KNXVAULT_AUTH_OIDC_ENABLED` | `false` |
| `KNXVAULT_AUTH_LDAP_ENABLED` | `false` |
| `KNXVAULT_AUDIT_FORWARD_ENABLED` | `false` |
| `KNXVAULT_ACME_RELATED_ENABLED` | `false` |

---

## Day-1 — First trusted use

1. Create policies and AppRole / K8s roles for **edge clients** (not root).
2. Issue private intermediate CA if needed (API or optional private operator).
3. Write critical KV paths; set rotation policies.
4. Revoke/rotate bootstrap root (short TTL under production profile).
5. Confirm monitoring scrapes **:8201** only (not API :8200).
6. Document break-glass unseal owners (Shamir if used).

### Explicit non-goals for Day-1 on base

| Do not | Why |
|--------|-----|
| Install CSI/ESO/webhook on this instance | N1 / N5 — use [platform-edge](platform-edge-day0-day1.md) |
| Enable public OIDC/LE | N1 — public TLS edge |
| Grant operator SA `get` on Secret `knxvault` | N3 / W86-01 |

---

## Related

- [Operator runbook](operator-runbook.md) · [seal-and-unseal recipe](../recipes/seal-and-unseal.md)  
- [Cross-instance trust](cross-instance-trust.md) · [Kubernetes deploy matrix](../deploy/kubernetes.md)
