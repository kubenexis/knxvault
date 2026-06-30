# Audit log forwarding

KNXVault can stream audit entries to an external HTTP sink for SIEM ingestion (Loki, Splunk HEC, custom collectors).

## Configuration

| Variable | Description |
|----------|-------------|
| `KNXVAULT_AUDIT_FORWARD_URL` | HTTP endpoint receiving `POST` with JSON audit entries |

Forwarding is **asynchronous** — `Record()` appends to the Raft-backed hash chain first, then posts a copy to the sink in a background goroutine. Failures do not block API requests.

## Payload format

Each POST body is a single `audit.Entry` JSON object:

```json
{
  "timestamp": "2026-06-30T12:00:00Z",
  "actor": "root",
  "action": "secret.read",
  "resource": "secrets/kv/app/config",
  "status": "success",
  "hash": "...",
  "signature": "..."
}
```

## Promtail / Loki pipeline (example)

```yaml
scrape_configs:
  - job_name: knxvault-audit-forwarder
    http_sd_configs:
      - url: http://audit-forwarder:8080/targets
    pipeline_stages:
      - json:
          expressions:
            actor: actor
            action: action
            resource: resource
      - labels:
          actor:
          action:
```

Point `KNXVAULT_AUDIT_FORWARD_URL` at a small reverse proxy or [Grafana Alloy](https://grafana.com/docs/alloy/latest/) HTTP receiver that writes to Loki.

## Operational notes

- Pull export (`GET /audit/export`) remains the authoritative integrity bundle with signed chain head.
- Per-entry `signature` is present when `KNXVAULT_AUDIT_SIGNING_KEY` is configured.
- Forwarding does not retry with backoff in MVP; monitor sink availability separately.