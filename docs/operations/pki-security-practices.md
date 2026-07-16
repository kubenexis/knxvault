# PKI Security Best Practices

Secure operations guide for KNXVault PKI — trust hierarchy, key handling, access control, revocation, and compliance-oriented practices.

## Trust hierarchy

### Do

| Practice | Rationale |
|----------|-----------|
| Use **root → intermediate → leaf** in production | Limits blast radius; root key used rarely |
| Keep root TTL **10+ years**; intermediate **3–5 years**; leaf **≤ 90 days** | Industry-aligned lifetimes |
| Issue leaf certs only from **intermediate** CAs | Root stays offline-eligible |
| Name CAs predictably (`org-root`, `org-intermediate`, `ingress-2026`) | Operational clarity in `role` field and audit |

### Avoid

| Anti-pattern | Risk |
|--------------|------|
| Issuing production workloads directly from root | Root compromise affects entire trust domain |
| Single CA for all purposes (client + server + code signing) | No segmentation for compromise or policy |
| TTL > 1 year on leaf certificates | Slow incident response; stale key exposure window |

## Private key protection

### What KNXVault encrypts

| Material | Storage |
|----------|---------|
| CA private keys | Encrypted (`PrivateKeyEnc` + `DEKEnc`) before Raft |
| Leaf private keys at rest | Returned to caller at issue time — **not** retained as cleartext in API response storage |
| CA certificates (PEM) | Cleartext in Raft (public) |
| Master key | `KNXVAULT_MASTER_KEY` / `KNXVAULT_MASTER_KEY_FILE` — env/Secret only |

See [ADR-0004](../adr/0004-encrypt-before-replication.md) and [security model](../architecture/security-model.md).

### Operator rules

1. **Never log** `private_key_pem` from issue responses
2. **Transit only over TLS** when moving keys to Kubernetes Secrets or hosts
3. **chmod 600** on key files; prefer tmpfs for short-lived material
4. **Do not commit** keys, tokens, or `KNXVAULT_MASTER_KEY` to Git
5. Store `KNXVAULT_MASTER_KEY` in sealed K8s Secret, KMS, or HSM path (Phase 4)

### Leaf key delivery

| Pattern | Security posture |
|---------|------------------|
| Issue → write K8s Secret in same Job | Good — minimize key lifetime in Job logs |
| Issue → CSI / inject render | Good — no key in pod env |
| Issue → operator pastes into ticket | **Bad** — avoid human-handled private keys |
| Auto-renew with `auto_renew: true` | Good — reduces manual re-issue; monitor renew audit events |

## Access control

### Principle of least privilege

| Actor | Minimum policy |
|-------|----------------|
| PKI administrator (human) | Custom policy: `pki/*` create/read/update/delete |
| Certificate automation (CronJob) | `pki/issue` + `pki/read` only — no `pki/root` |
| Workload (read trust bundle) | `pki/read` on export paths only |
| Audit reviewer | `audit/export:read` — no PKI write |

Default `pki-admin` grants full `pki/*` — suitable for bootstrap, then replace with scoped policies.

### Token hygiene

```bash
# After bootstrap, create scoped token — disable root token use
curl -s -X POST $KNXVAULT_ADDR/auth/token/create \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"policies": ["pki-operator"], "ttl": "8h"}'
```

- Prefer **Kubernetes SA auth** for in-cluster issuers (no static token in manifests)
- Enable `KNXVAULT_RATE_LIMIT_ENABLED=true` in production
- Consider `KNXVAULT_REQUEST_SIGNING_REQUIRED=true` for break-glass admin paths

### Seal during maintenance

```bash
knxvault-cli sys seal    # blocks mutating operations
# perform maintenance
knxvault-cli sys unseal "<base64-unseal-key>"
```

Seal does not erase keys; it blocks writes until unseal. When Raft is enabled, **`KNXVAULT_UNSEAL_KEY` is required** at startup and **must differ** from `KNXVAULT_MASTER_KEY`. Configure and back up unseal with the same custody as the master key — not optional in production Raft.

## Certificate content

### Key sizes

| Tier | Recommended `key_bits` |
|------|------------------------|
| Root / intermediate | `4096` |
| Leaf (general TLS) | `2048` or `4096` |
| High-throughput services | `2048` (balance performance) |

### Subject and SANs

- Always set **`dns_names`** matching actual client/server hostnames
- Use **`ip_addresses`** only when clients connect by IP
- Wildcard SANs (`*.app.example.com`) increase risk — restrict via PKI role `allowed_domains` when roles are configured via backup/snapshot

### Auto-renew

Enable for production leaf certs:

```json
{"auto_renew": true}
```

Tune:

| Variable | Guidance |
|----------|----------|
| `KNXVAULT_RENEW_GRACE` | ≥ 2× maximum expected renewal pipeline latency |
| `KNXVAULT_JOB_CERT_RENEW_INTERVAL` | ≤ 1/4 of shortest leaf TTL |

## Revocation and incident response

### Routine revocation

Revoke on:

- Key compromise or suspected leak
- Decommissioned service
- Employee / SA credential rotation with cert-bound identity

```bash
curl -s -X POST $KNXVAULT_ADDR/pki/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ca_id":"<uuid>","serial":"<serial>","reason":"cessationOfOperation"}'
```

Distribute updated CRL (`GET /pki/crl/:id`) or configure clients for OCSP (`POST /pki/ocsp/:id`).

### CA compromise

Follow [CA compromise runbook](runbooks/ca-compromise.md):

1. Network isolate KNXVault
2. Revoke unauthorized serials
3. Rotate intermediate (or root if needed)
4. Re-issue all legitimate leaf certs
5. Audit export + `POST /audit/verify`

## Audit and compliance

| Control | Configuration |
|---------|---------------|
| Tamper-evident audit | `KNXVAULT_AUDIT_SIGNING_KEY` |
| SIEM forwarding | `KNXVAULT_AUDIT_FORWARD_URL` |
| PKI event review | Filter audit for `pki.root`, `pki.issue`, `pki.revoke`, `pki.renew` |

Audit **redacts** password/token fields in `details` — still avoid placing PEM private keys in custom integration payloads.

## Network and TLS

### KNXVault API

```yaml
security:
  tls_cert: /etc/knxvault/tls/server.pem
  tls_key: /etc/knxvault/tls/server.key
  rate_limit_enabled: true
  rate_limit_rpm: 300
```

### Kubernetes

- Restrict KNXVault `Service` with `NetworkPolicy` — allow only CSI, cert issuer, and admin CIDRs
- Do not expose `/metrics` publicly without auth fronting
- Use internal DNS (`knxvault.knxvault.svc.cluster.local`) for in-cluster issuers

## Backup and disaster recovery

| Requirement | Practice |
|-------------|----------|
| Encrypted backups before PKI changes | `knxvault-cli backup create` |
| Master key escrow | Secure offline copy of `KNXVAULT_MASTER_KEY` |
| Restore testing | Quarterly restore drill with same master key |
| Cross-cluster migration | Backup/restore — not CA PEM export alone |

CA private keys are **inside** the backup archive (encrypted). PEM export (`GET /pki/ca/:id/export`) returns certificates and chain, not private keys.

## Development vs production

| Setting | Development | Production |
|---------|-------------|------------|
| CA hierarchy | Single root acceptable | Root + intermediate |
| `KNXVAULT_JWT_SECRET` | Optional local dev | **Never** |
| `KNXVAULT_K8S_AUTH_INSECURE` | Dev only, Raft off | **Never** |
| Leaf TTL | `720h` acceptable | `≤ 2160h` (90d), prefer shorter |
| Trust distribution | Self-signed root in local trust store | Proper chain + change management |

## Checklist (production PKI)

- [ ] Root + intermediate hierarchy created; root not used for leaf issuance
- [ ] Scoped `pki-operator` policy; bootstrap root token rotated out
- [ ] Leaf certs use `auto_renew: true` with tuned `KNXVAULT_RENEW_GRACE`
- [ ] `KNXVAULT_AUDIT_SIGNING_KEY` enabled
- [ ] KNXVault API served over TLS
- [ ] CRL/OCSP distribution documented for relying parties
- [ ] [CA compromise runbook](runbooks/ca-compromise.md) accessible to on-call
- [ ] Encrypted backup schedule includes PKI state
- [ ] Kubernetes issuers use SA auth, not static tokens
- [ ] cert-manager integration plan documented (W40-02 or CronJob interim)

## Related documents

- [PKI administration](pki-administration.md)
- [PKI Kubernetes integration](pki-kubernetes.md)
- [Operator security](operator-security.md)
- [Security model](../architecture/security-model.md)
- [CA compromise runbook](runbooks/ca-compromise.md)