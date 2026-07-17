<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Runbook: CA Private Key Compromise

**Severity:** Critical  
**Estimated time:** 1–4 hours depending on downstream impact

## Symptoms

- Unauthorized certificates observed in the wild
- Audit log shows unexpected `pki.issue` or `pki.root` actions
- External report of leaked CA key material

## Immediate actions (0–30 minutes)

1. **Isolate the cluster** — apply NetworkPolicy to block ingress except break-glass admin IPs
2. **Revoke suspected certificates** — for each unauthorized serial:

```bash
curl -s -X POST $KNXVAULT_ADDR/pki/revoke \
  -H "Authorization: Bearer $BREAKGLASS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ca_id":"<compromised-ca-id>","serial":"<serial>","reason":"keyCompromise"}'
```

3. **Publish updated CRL** — `GET /pki/crl/<ca_id>` and distribute to relying parties
4. **Rotate admin tokens** — invalidate bootstrap root token; issue new scoped tokens

## Assess scope

```bash
# Export audit log
curl -s $KNXVAULT_ADDR/audit/export \
  -H "Authorization: Bearer $BREAKGLASS_TOKEN" > audit-incident.json

# List issued certificates for the CA
curl -s "$KNXVAULT_ADDR/pki/ca/<ca_id>" \
  -H "Authorization: Bearer $BREAKGLASS_TOKEN"
```

Identify all serials issued during the compromise window. Revoke each.

## Recovery paths

### Option A: Intermediate CA compromise (root intact)

1. Revoke the compromised intermediate CA serial on the parent
2. Create a new intermediate CA chained to the existing root
3. Re-issue all leaf certificates under the new intermediate
4. Update workloads via injection API or cert-manager integration

### Option B: Root CA compromise

1. **Create a new root CA** with a distinct name and trust anchor
2. Issue a fresh intermediate chain
3. Re-issue all leaf certificates
4. Distribute new root trust bundle to all clients
5. Mark the old root as `revoked` in KNXVault and remove from trust stores

```bash
curl -s -X POST $KNXVAULT_ADDR/pki/root \
  -H "Authorization: Bearer $BREAKGLASS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"root-2026","common_name":"KNXVault Root CA 2026","ttl":"8760h"}'
```

### Option C: Full vault state untrusted

If the master key may also be compromised:

1. Provision a **new KNXVault cluster** with a new master key
2. Restore only verified-good secrets from an offline backup predating the incident
3. Do not restore CA key material from the compromised period

## Post-incident

| Task | Owner |
|------|-------|
| Root cause analysis | Security team |
| Update policies (least privilege on `pki/*`) | Platform team |
| Enable request signing | `KNXVAULT_REQUEST_SIGNING_REQUIRED=true` |
| Review audit chain integrity | `POST /audit/verify` |
| Document new trust anchors | PKI consumers |

## Prevention

- Scope `pki/*` write access to a dedicated PKI admin role
- Enable audit signing (`KNXVAULT_AUDIT_SIGNING_KEY`)
- Store master key in a sealed K8s Secret or external KMS (Phase 4 HSM)
- Monitor `pki.issue` rate in Grafana

## Related documents

- [PKI administration](../pki-administration.md)
- [PKI security best practices](../pki-security-practices.md)
- [PKI Kubernetes integration](../pki-kubernetes.md)
- [Security model](../../architecture/security-model.md)
- [Day-2 operations](../day2.md)