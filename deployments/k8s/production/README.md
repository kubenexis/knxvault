# knxvault production overlay (W75-02 / M-DTP)

CIS-oriented Day-0 install: **production security profile** + tighter NetworkPolicy.
**Base surface only** — no CSI, ESO, webhook, or ACME egress (compose via `../components/`).

## Prerequisites

1. Cluster with NetworkPolicy enforcement (Calico, Cilium, etc.).  
2. Labels for client namespaces (examples):
   - Ingress controller ns: `kubernetes.io/metadata.name=ingress-nginx` (or edit NetPol).  
   - Monitoring ns: `kubernetes.io/metadata.name=monitoring` (scrapes **:8201 only** — W86-07).  
   - API clients (operator/CSI): `knxvault.kubenexis.dev/api-client=true`.  
   - Unseal jump ns: `knxvault.kubenexis.dev/unseal-client=true`.  
3. Secrets in `deployments/k8s/secret.yaml` (or sealed-secrets) including:
   - `KNXVAULT_MASTER_KEY`
   - `KNXVAULT_UNSEAL_KEY` (≠ master) **or** auto-unseal ciphertext+KEK
   - `KNXVAULT_AUDIT_SIGNING_KEY` (**required** by production profile)
   - `KNXVAULT_METRICS_BEARER_TOKEN` (**required** by production profile)
   - Optional bootstrap `KNXVAULT_ROOT_TOKEN` (short-lived; rotate after Day-0)
4. **Raft mTLS** Secret `knxvault-raft-tls` (`tls.crt` / `tls.key` / `ca.crt`) — W86-06. Replace placeholders in `raft-mtls/secret.yaml` before multi-node apply.
5. ConfigMap production patch sets `KNXVAULT_METRICS_ADDR=:8201`, feature gates off, and `KNXVAULT_UNSEAL_ALLOW_CIDRS` (adjust for your CNI).

## Apply

```bash
# Review / edit secret values first — never commit real keys.
kubectl apply -k deployments/k8s/production
# Airgap core (same surface, gates forced):
# kubectl apply -k deployments/k8s/overlays/airgap-core
```

Multi-node Raft **forces** production profile in the binary unless  
`KNXVAULT_SECURITY_PROFILE=lab` **and** `KNXVAULT_RAFT_ALLOW_INSECURE=true` (lab only).

## Verify

```bash
kubectl -n knxvault get networkpolicy
kubectl -n knxvault get cm knxvault -o yaml | grep -E 'SECURITY_PROFILE|AUTH_OIDC|RAFT_MTLS'
# After pods ready + unseal:
knxvault-cli doctor --profile production --json --addr https://knxvault.example.com \
  --feature-oidc=false --feature-ldap=false --feature-audit-forward=false --feature-acme=false
# expect fail:0 (https + token required for production gate)
make dtp-surface   # CI: base/production must not include CSI/ESO/webhook/ACME
```

## Unseal

Unseal is unauthenticated by design. This overlay **only** allows unseal traffic from namespaces labeled `knxvault.kubenexis.dev/unseal-client=true`. Do **not** put Service type LoadBalancer/NodePort on the public internet.

## Related

- [Distributed Trust Platform](../../../docs/design/distributed-trust-platform.md)  
- [Instance roles](../../../docs/operations/instance-roles.md)  
- [CIS hardening design](../../../docs/design/cis-hardening-improvements.md)  
- [Production security posture](../../../docs/design/production-security-posture.md)  
- [Operator security](../../../docs/operations/operator-security.md)  
