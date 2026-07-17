<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Distributed Tracing

KNXVault supports OpenTelemetry HTTP tracing when enabled.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_TRACING_ENABLED` | `false` | Enable OTLP HTTP export |
| `KNXVAULT_OTLP_ENDPOINT` | _(collector default)_ | OTLP HTTP endpoint host:port |
| `KNXVAULT_TRACING_SAMPLE_RATIO` | `0` (effective `1` when tracing enabled) | Trace sampling ratio (0–1) |

## Jaeger / Tempo example

```bash
export KNXVAULT_TRACING_ENABLED=true
export KNXVAULT_OTLP_ENDPOINT=localhost:4318
./build/bin/knxvault serve
```

Gin requests are instrumented with service name `knxvault`. Propagate `traceparent` headers from upstream clients for correlated traces.

## Grafana

Import [`deployments/grafana/knxvault-overview.json`](../../deployments/grafana/knxvault-overview.json) for Prometheus metrics dashboards. Pair with your tracing backend for request drill-down.