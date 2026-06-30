# Observability — Prometheus Metrics

KNXVault exposes Prometheus metrics at **`GET /metrics`** (unauthenticated; restrict at the network layer in production).

## Scrape configuration

```yaml
scrape_configs:
  - job_name: knxvault
    metrics_path: /metrics
    static_configs:
      - targets: ["knxvault:8200"]
```

Kubernetes manifests include pod annotations:

```yaml
prometheus.io/scrape: "true"
prometheus.io/path: "/metrics"
prometheus.io/port: "8200"
```

## Exported metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `knxvault_http_requests_total` | Counter | `method`, `route`, `status` | Total HTTP requests |
| `knxvault_http_request_duration_seconds` | Histogram | `method`, `route` | Request latency |
| `knxvault_build_info` | Gauge | `version` | Build version (always 1) |

Go runtime metrics are also exposed via the default Prometheus registry.

## Structured logging

Every HTTP request logs:

- `request_id` — from `X-Request-ID` header (generated if absent)
- `actor` — authenticated subject or `anonymous`
- `method`, `path`, `route`, `status`, `latency`, `client_ip`

## Example queries

```promql
# Request rate by route
sum(rate(knxvault_http_requests_total[5m])) by (route)

# p95 latency
histogram_quantile(0.95, sum(rate(knxvault_http_request_duration_seconds_bucket[5m])) by (le, route))

# 5xx error ratio
sum(rate(knxvault_http_requests_total{status=~"5.."}[5m]))
/
sum(rate(knxvault_http_requests_total[5m]))
```