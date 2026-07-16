# Lab E2E — e2e-test01 (192.168.137.131) — historical core-only

> **Superseded for the full gate.** Prefer **[lab-full-e2e.md](lab-full-e2e.md)** (`make lab-full-e2e`): **53/53 PASS**, including **Shamir multi-share unseal**, Vault product profile, operator CRDs, and multi-issuer.  
> Map of all layers: [e2e-and-lab-tests.md](e2e-and-lab-tests.md).  
> This page remains as a **historical** core-only single-key smoke record (20 checks, full-key unseal).

| Field | Value |
|-------|-------|
| **Result** | **PASS** (20 / 20 checks) — historical |
| **Date (UTC)** | 2026-07-16T02:07:26Z |
| **Host** | `e2e-test01.example.local` (`192.168.137.131`) |
| **Binary** | `knxvault` / `knxvault-cli` **0.4.5** @ commit `b973d53` |
| **Mode** | Single-node Dragonboat Raft (host process, not K8s STS) |
| **Unseal** | Full-key `POST /sys/unseal` (not multi-share) |
| **Listen** | HTTP `:8200`, Raft `127.0.0.1:63001` |
| **OpenSSL** | 3.5.6 (host) |

## Why host process (not 3-replica StatefulSet)

The production manifests expect a **3-replica** Raft StatefulSet. A single lab node cannot schedule three Raft peers with distinct pod IDs and PVCs without multi-node capacity. This E2E validates the same core product surface the integration harness covers (`test/integration/e2e_daemon_test.go`), but with **Raft enabled** (production storage path) on one node:

- SCP static binaries built on the build host (`make build` → `bin/knxvault`, `bin/knxvault-cli`)
- Run `/opt/knxvault/knxvault serve` under root with env-based config
- Exercise CLI + HTTP API for health, doctor, auth, KV, PKI, metrics

## Environment (lab)

```bash
# On 192.168.137.131
export KNXVAULT_MASTER_KEY="$(cat /opt/knxvault/e2e-master.key)"   # openssl rand -base64 32
export KNXVAULT_UNSEAL_KEY="$(cat /opt/knxvault/e2e-unseal.key)"   # MUST differ from master when Raft on
export KNXVAULT_ROOT_TOKEN="$(cat /opt/knxvault/e2e-root.token)"   # e2e-root-token-131
export KNXVAULT_HTTP_ADDR=':8200'
export KNXVAULT_LOG_LEVEL=info
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/var/lib/knxvault/raft-e2e
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001
export KNXVAULT_RAFT_LEADER_WAIT=30s

nohup /opt/knxvault/knxvault serve > /var/log/knxvault/e2e-serve.log 2>&1 &
```

Artifact layout on the node:

| Path | Purpose |
|------|---------|
| `/opt/knxvault/knxvault` | Server binary |
| `/opt/knxvault/knxvault-cli` | CLI |
| `/opt/knxvault/e2e-*.key` / `e2e-root.token` | Bootstrap secrets (mode 600) |
| `/var/lib/knxvault/raft-e2e` | Raft data dir |
| `/var/log/knxvault/e2e-serve.log` | Serve log |
| `/opt/knxvault/e2e-results.txt` | Last smoke transcript |

## Checks executed

Aligned with `TestE2EDaemonCLIWorkflow` plus production readiness signals:

| # | Check | Result |
|---|-------|--------|
| 1 | `knxvault-cli health` → healthy, leader, raft_ready, unsealed | PASS |
| 2 | `knxvault-cli status` → ready | PASS |
| 3 | `knxvault-cli doctor --json` → healthy, fail=0 (1 warn: http not https) | PASS |
| 4 | `POST /auth/token` root bootstrap token → admin policies | PASS |
| 5 | `pki root` create CA | PASS |
| 6 | `pki issue` leaf cert + private key PEM | PASS |
| 7 | `kv put` secret | PASS |
| 8 | `kv get --show-secrets` plaintext value | PASS |
| 9 | `kv get` redacted → `[REDACTED]` | PASS |
| 10 | `GET /metrics` HTTP 200 + Prometheus series | PASS |
| 11 | `GET /openapi.yaml` HTTP 200 | PASS |
| 12–13 | `GET /health`, `GET /ready` via curl | PASS |
| 14–15 | Env-only CLI (`KNXVAULT_ADDR` / `KNXVAULT_TOKEN`) KV put/get | PASS |
| 16–19 | Asserts: redaction, secret value, unsealed+raft_ready, doctor healthy | PASS |
| 20 | API `POST /pki/issue` PEM structure | PASS |

**Summary: PASS=20 FAIL=0**

Sample health payload:

```json
{
  "status": "healthy",
  "version": "0.4.5",
  "leader": true,
  "ha_enabled": true,
  "raft_enabled": true,
  "raft_ready": true,
  "sealed": false
}
```

Doctor noted one **warn** only: API over plain HTTP (expected for lab host process without TLS certs).

## Failure found and fixed during this run

| Symptom | Cause | Fix |
|---------|-------|-----|
| `serve` exits immediately; curl `:8200` exit 7 | First attempt set `KNXVAULT_RAFT_ENABLED=true` without `KNXVAULT_UNSEAL_KEY` | Generate a **separate** base64-32 unseal key (`openssl rand -base64 32`). Must not equal master key. |

Log line:

```text
Error: unseal key is required when raft is enabled (set KNXVAULT_UNSEAL_KEY)
```

## Learnings

1. **Raft + unseal is mandatory** — docs default for `KNXVAULT_UNSEAL_KEY` looks optional, but startup **fails** when Raft is enabled and the key is unset. Recipe and config table should treat it as required for Raft.
2. **Unseal ≠ master** — envelope master key and unseal key are distinct; reusing the same value is rejected when Raft is on.
3. **Single-node Raft is enough for API/CLI E2E** on a single lab host; full HA (failover, membership) still needs multi-node Profile A/B from [manual-testing-strategy.md](manual-testing-strategy.md).
4. **3-replica K8s STS** is out of scope for a single-node lab without multi-pod scheduling capacity.
5. **Distroless / cluster image load** not used here: same air-gap pattern as other lab e2e (static binary + host process). Cluster deploy remains for multi-node or when Harbor/image load is available.
6. Host OpenSSL 3.x is present and used for key material and PKI backend.

## Not covered (follow-ups)

- 3-node Raft failover / membership (needs ≥3 nodes or multi-process Profile A)
- Kubernetes auth (TokenReview), OIDC, CSI, webhook injection
- Seal/unseal cycle via API after start, backup/restore
- TLS on `:8200` and Raft mTLS
- Container image load into lab registry + StatefulSet

## Re-run procedure (short)

```bash
# Build host
cd /path/to/knxvault && make build
scp bin/knxvault bin/knxvault-cli root@192.168.137.131:/opt/knxvault/

# Lab node — clean raft dir, new keys, start, smoke (see Environment + Checks)
```

## Doc updates driven by this E2E

Learnings from this run were folded into user/admin docs:

- [Installation guide](../installation/install.md) — single-node Raft env, unseal required, post-install verify
- [Kubernetes deploy](../deploy/kubernetes.md) + [`secret.yaml`](../../deployments/k8s/secret.yaml) — `KNXVAULT_UNSEAL_KEY`
- [Getting started](../user/getting-started.md) — `doctor`, KV redaction / `--show-secrets`
- [Operator security](../operations/operator-security.md) — master vs unseal custody
- [Deploy 3-node recipe](../recipes/deploy-3-node-cluster.md) — generate unseal; CrashLoop troubleshooting

## See also

- [Local dev single-node recipe](../recipes/local-dev-single-node.md)
- [Configuration reference](../installation/configuration.md)
- Integration E2E harness: `test/integration/e2e_daemon_test.go`
- [Manual testing strategy](manual-testing-strategy.md)
