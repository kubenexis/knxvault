<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Platform-edge Day-0 / Day-1 (injection + sync)

**Audience:** Operators standing up a **platform-edge** instance for CSI, mutating webhook, and External Secrets.  
**Principles:** [`AGENTS.md`](../../AGENTS.md) **N1–N3** · [instance-roles.md](instance-roles.md) · [cross-instance-trust.md](cross-instance-trust.md)

Edge holds **no master/unseal**. It authenticates to **core** (or its own vault with non-critical material) with scoped policies.

---

## Topology options

| Option | Description |
|--------|-------------|
| **A. Edge as client of core** | Separate vault instances; edge SA/AppRole on **core** for `secrets/kv/apps/*` only |
| **B. Single-cluster edge overlay** | Same cluster: `overlays/platform-edge` on a vault already used for apps (still **not** airgap custody ideal) |

Prefer **A** for regulated custody.

---

## Day-0 — Bring-up

### 0.1 Compose surface

```bash
# Includes production base + CSI + webhook + ESO components
kubectl apply -k deployments/k8s/overlays/platform-edge
```

Gates on this overlay may enable OIDC for federation (`KNXVAULT_AUTH_OIDC_ENABLED=true`); LDAP/ACME stay off unless required.

### 0.2 Core trust setup (on core instance)

1. Create policy `edge-read` (KV read on app paths only; deny `sys/*`, `pki/ca` write).
2. Bind K8s role for CSI/ESO SAs.
3. Issue short-lived tokens; never give edge the custody Secret.

### 0.3 CSI (add-on)

- Deploy Secrets Store CSI Driver (upstream images; airgap must mirror them).
- Provider: `deployments/csi/` (same `knxvault` image, command `knxvault-csi`).
- Recipe: [csi-driver-integration.md](../recipes/csi-driver-integration.md)

### 0.4 Mutating webhook (add-on) — W86-13

1. Create TLS Secret from `deployments/k8s/webhook/tls-secret-template.yaml` (real certs).
2. Apply `deployments/k8s/webhook/deployment.yaml`.
3. Set `MutatingWebhookConfiguration` **caBundle** (base64 CA) or cert-manager inject annotation — **do not** leave `REPLACE_WITH_BASE64_CA` in production.

```bash
# Example caBundle patch after generating CA
CA_B64=$(base64 -w0 ca.crt)
kubectl patch mutatingwebhookconfiguration knxvault-inject --type=json \
  -p "[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\"value\":\"${CA_B64}\"}]"
```

### 0.5 External Secrets (add-on) — W86-04 / W86-05

1. Create TLS Secret `knxvault-eso-tls` (`tls.crt` / `tls.key`).
2. Create caller Secret `knxvault-eso-caller` with key `token` = **scoped** vault token (not root).
3. Apply ESO adapter + ClusterSecretStore:

```bash
kubectl apply -f deployments/external-secrets/knxvault-eso-deployment.yaml
kubectl apply -f deployments/external-secrets/clustersecretstore-webhook.yaml
```

- Adapter listens **HTTPS :8443** (TLS required unless lab `KNXVAULT_ESO_ALLOW_PLAINTEXT`).
- Unauthenticated `/fetch` returns **401**; TokenFile alone does **not** proxy (unless `KNXVAULT_ESO_ALLOW_TOKEN_FILE_PROXY=true` break-glass).
- ClusterSecretStore URL is `https://…:8443/fetch` with Authorization bearer from caller Secret.

Recipe: [external-secrets-operator.md](../recipes/external-secrets-operator.md)

### 0.6 Verify

```bash
kubectl -n knxvault get deploy knxvault-eso knxvault-webhook
kubectl -n knxvault get secret knxvault-eso-tls knxvault-webhook-tls
# Adapter rejects unauthenticated fetch
curl -sk -X POST https://knxvault-eso.knxvault.svc:8443/fetch -d '{"path":"x"}' -w '%{http_code}\n' -o /dev/null
# expect 401
```

---

## Day-1 — First apps

1. Annotate workloads for CSI or ExternalSecret as needed.
2. Confirm edge policies cannot read custody paths or unseal.
3. Rotate scoped ESO caller token on a schedule.
4. Optional: enable OIDC on **edge only** for developer federation.
5. Public LE stays on a **separate public-TLS-edge** (`KNXVAULT_OPERATOR_ACME_ENABLED=true` + ACME egress component) — not on airgap core.

---

## Capability on the right plane (Phase C)

| Capability | Where |
|------------|--------|
| Critical secrets + private CA + seal | **Base / airgap-core** |
| CSI file mount, webhook inject, ESO sync | **Platform-edge** |
| Public ACME/LE | **Public TLS edge** |
| In-tree engines (transit, wrap, leases) | Base API under RBAC (not a new pod) |
| HSM / KMS auto-unseal | Base custody (M-CUSTODY-1) |

---

## Related

- [Base Day-0/Day-1](base-day0-day1.md) · [AGENTS.md](../../AGENTS.md)  
- [Operator security](operator-security.md) · [build-and-deploy-images](build-and-deploy-images.md)
