# Recipe: Audit SIEM forwarding

Stream audit events to Splunk, Elastic, Loki, or any HTTP collector in real time.

## What you will learn

- Configuring `KNXVAULT_AUDIT_FORWARD_URL`
- Payload format for SIEM parsers
- Relationship between live forwarding and authoritative export

## Prerequisites

- KNXVault cluster with audit enabled
- Reachable HTTP endpoint for your SIEM or a mock collector
- Optional: `KNXVAULT_AUDIT_SIGNING_KEY` for export verification

## Concepts

```
API request  →  audit.Record()  →  Raft hash chain (authoritative)
                              └→  async HTTP POST to SIEM (copy)
```

Forwarding is **non-blocking** — SIEM downtime does not fail API requests. For compliance proof, use [Audit export](audit-export.md) as the integrity bundle.

## Step 1 — Deploy a test collector (optional)

```bash
kubectl -n knxvault apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: audit-collector
spec:
  replicas: 1
  selector:
    matchLabels:
      app: audit-collector
  template:
    metadata:
      labels:
        app: audit-collector
    spec:
      containers:
        - name: server
          image: mendhak/http-https-echo:31
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: audit-collector
spec:
  selector:
    app: audit-collector
  ports:
    - port: 8080
      targetPort: 8080
EOF
```

## Step 2 — Configure KNXVault

Add to `deployments/k8s/configmap.yaml` or `secret.yaml`:

```yaml
KNXVAULT_AUDIT_FORWARD_URL: "http://audit-collector.knxvault.svc:8080/audit"
KNXVAULT_AUDIT_SIGNING_KEY: "<random-hex-from-openssl-rand-hex-32>"
```

Rolling restart (one pod at a time):

```bash
for i in 2 1 0; do kubectl -n knxvault delete pod knxvault-$i --wait=true; done
```

## Step 3 — Generate traffic

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

knxvault-cli kv put siem/demo value=forward-test
knxvault-cli kv get siem/demo --show-secrets
```

## Step 4 — Confirm delivery

```bash
kubectl -n knxvault logs deployment/audit-collector --tail=50
```

Each POST body is a single JSON `audit.Entry`:

```json
{
  "timestamp": "2026-07-01T12:00:00Z",
  "actor": "root",
  "action": "secret.read",
  "resource": "secrets/kv/siem/demo",
  "status": "success",
  "hash": "...",
  "signature": "..."
}
```

## SIEM integration examples

### Splunk HTTP Event Collector (HEC)

Point a small forwarder proxy at Splunk:

```bash
KNXVAULT_AUDIT_FORWARD_URL=https://splunk-hec:8088/services/collector/event
# Proxy adds Authorization: Splunk <hec-token> header
```

### Grafana Loki via Alloy

Configure an Alloy `loki.source.api` receiver; set `KNXVAULT_AUDIT_FORWARD_URL` to the Alloy HTTP endpoint. Parse JSON fields `actor`, `action`, `resource` as labels.

### Elastic ingest

Use Logstash `http` input on port 8080; map fields to ECS:

| KNXVault field | ECS field |
|----------------|-----------|
| `actor` | `user.name` |
| `action` | `event.action` |
| `resource` | `event.dataset` |
| `status` | `event.outcome` |

## Operational notes

| Topic | Guidance |
|-------|----------|
| **Retries** | MVP forwarder does not retry with backoff — monitor sink health |
| **Authoritative source** | `GET /audit/export` + `audit/verify` for audits |
| **Volume** | High-traffic clusters — size SIEM ingestion accordingly |
| **PII** | `actor` may contain usernames; classify per policy |

## Verify

```bash
# Forwarder received events within 5s of API call
# Export still verifies independently
curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(curl -s $KNXVAULT_ADDR/audit/export?limit=5 -H "Authorization: Bearer $KNXVAULT_TOKEN")" | jq .
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| No events at collector | URL wrong; NetworkPolicy blocks egress; restart after config change |
| Duplicate events | Expected during leader failover — dedupe by hash in SIEM |
| API slow | Forwarding should be async — check unrelated causes |

## Related recipes

- [Audit export](audit-export.md)
- [Deploy 3-node cluster](deploy-3-node-cluster.md)

## See also

- [Audit forwarding](../observability/audit-forwarding.md)