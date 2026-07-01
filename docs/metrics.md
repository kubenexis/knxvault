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
| `knxvault_leader` | Gauge | — | `1` when this instance is the HA leader |
| `knxvault_leader_election_running` | Gauge | — | `1` while the leader election goroutine is active; `0` after unexpected exit (`/ready` returns 503 when HA/Raft enabled) |
| `knxvault_raft_leader` | Gauge | — | `1` when this node is the Raft leader |
| `knxvault_raft_term` | Gauge | — | Current Raft term |
| `knxvault_raft_commit_index` | Gauge | — | Committed Raft log index |
| `knxvault_raft_propose_duration_seconds` | Histogram | — | Vault command propose latency |
| `knxvault_rate_limited_total` | Counter | — | Requests rejected by rate limiter |
| `knxvault_active_leases` | Gauge | — | Cluster-wide active (non-expired, non-revoked) database leases on leader tick |
| `knxvault_openssl_breaker_open` | Gauge | — | `1` when OpenSSL circuit breaker is open |
| `knxvault_raft_tls_enabled` | Gauge | — | `1` when Raft peer mTLS is configured |

Go runtime metrics are also exposed via the default Prometheus registry.

## Grafana dashboard

Import [`deployments/grafana/knxvault-overview.json`](../../deployments/grafana/knxvault-overview.json) for request rate, latency, HA leader, rate limiting, and lease panels.

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