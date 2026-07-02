# Audit log forwarding

KNXVault can stream audit entries to an external HTTP sink for SIEM ingestion (Loki, Splunk HEC, custom collectors).

## Configuration

| Variable | Description |
|----------|-------------|
| `KNXVAULT_AUDIT_FORWARD_URL` | HTTP endpoint receiving `POST` with JSON audit entries |

Forwarding is **asynchronous** — `Record()` appends to the Raft-backed hash chain first, then posts a copy to the sink in a background goroutine. Failures do not block API requests.

## Payload format

Each POST body is a single `audit.Entry` JSON object. Authentication events (W43-02) include top-level enriched fields in addition to `details`:

```json
{
  "timestamp": "2026-06-30T12:00:00Z",
  "actor": "10.0.0.5",
  "action": "auth.login.failed",
  "resource": "auth/kubernetes",
  "status": "failure",
  "auth_method": "kubernetes",
  "source_ip": "10.0.0.5",
  "request_id": "req-abc123",
  "failure_reason": "role not found",
  "details": {
    "auth_method": "kubernetes",
    "source_ip": "10.0.0.5",
    "request_id": "req-abc123",
    "failure_reason": "role not found"
  },
  "hash": "...",
  "signature": "..."
}
```

`GET /audit/export` returns the same enriched fields on each `AuditEntryResponse` row.

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