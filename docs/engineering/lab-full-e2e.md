<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Lab full E2E — e2e-test01 (192.168.137.131)

| Field | Value |
|-------|-------|
| **Result** | **PASS** (53 / 53 checks) |
| **Date (UTC)** | 2026-07-16T08:31:57Z |
| **Host** | `e2e-test01` (`192.168.137.131`) |
| **Binary** | `knxvault` / `knxvault-cli` / `knxvault-operator` **0.5.1** |
| **Mode** | Single-node Dragonboat Raft (host process) + operator against local API |
| **Unseal** | **Shamir multi-share** — start sealed → offline t-of-n shares → data plane (no full-key unseal on open path) |
| **Script** | `scripts/lab-full-e2e.sh` |

## What it covers

| Section | Checks | Purpose |
|---------|--------|---------|
| **core** | 20 | CLI health/status/doctor, auth, PKI, KV redaction, metrics/openapi, env-only CLI |
| **multishare** | 12 | Bootstrap multi-share open + re-seal ceremony (progress, alternate share pair, data plane) |
| **vaultcompat** | 14 | Vault product profile: health, AppRole, sign (issue+CSR), custom mount |
| **operator** | 4 | Vault-mode ClusterIssuer Ready, Certificate serial+caId, TLS Secret |
| **multi-issuer** | 3 | SelfSigned ClusterIssuer + Certificate + Secret (no cert-manager) |

## Shamir multi-share unseal (ops flow)

This is the production-style ceremony exercised on the lab host:

```text
1. Generate master + unseal keys on lab
2. Offline split on build host: go run ./scripts/shamir-split -key $UNSEAL -n 3 -t 2
3. Install share files on lab (/opt/knxvault/e2e-share-{1,2,3}.b64)
4. Start knxvault serve with KNXVAULT_UNSEAL_THRESHOLD=2  → sealed
5. POST /sys/unseal {"share": share1}  → sealed, progress=1, threshold=2
6. POST /sys/unseal {"share": share2}  → unsealed
7. KV write proves data plane open (MULTISHARE_UNSEAL_OK)
8. Later: re-seal → share1 alone still sealed → shares 1+3 unseal → KV write again
```

**Full unseal key is never submitted** for the open path. Share 3 is held as a spare custodian share for the re-seal ceremony.

Offline split tool: `scripts/shamir-split/main.go` (same `internal/crypto/shamir` package as the server combine path).  
`POST /sys/generate-unseal-shares` is also checked **while unsealed** (admin tooling); it remains seal-guarded when sealed.

## Re-run

```bash
cd /path/to/knxvault
bash scripts/lab-full-e2e.sh                 # default host 192.168.137.131
bash scripts/lab-full-e2e.sh 192.168.137.131
# or
make lab-full-e2e
```

Requires: SSH as `root` to the lab host, `kubectl` on the host, OpenSSL, Go (for offline split), `make build build-cli build-operator` on the build machine.

Artifacts on the lab node:

| Path | Purpose |
|------|---------|
| `/opt/knxvault/knxvault{,-cli,-operator}` | Binaries under test |
| `/opt/knxvault/e2e-unseal.key` | Full unseal secret (configured at process start; not used for HTTP open path) |
| `/opt/knxvault/e2e-share-{1,2,3}.b64` | Offline Shamir custodian shares |
| `/var/lib/knxvault/raft-full` | Fresh Raft data dir for this run |
| `/var/log/knxvault/full-e2e-serve.log` | Server log |
| `/var/log/knxvault/full-e2e-operator.log` | Operator log |
| `/opt/knxvault/e2e-full-results.txt` | Last check transcript |

## Last run summary

```
START_SEALED_OK
SHARE1_PROGRESS_OK
MULTISHARE_UNSEAL_OK
SUMMARY|PASS=53 FAIL=0
FULL LAB E2E PASS on 192.168.137.131
```

### multishare section (W53)

- Bootstrap KV after multi-share unseal  
- Offline shares present (n=3)  
- Re-seal → KV 503 → share1 progress → shares 1+3 open data plane  
- `generate-unseal-shares` while unsealed  

### vaultcompat / operator

- Unchanged from prior lab full E2E (AppRole, vault sign, ClusterIssuer, Certificate Secret)  

## Local integration E2E

```bash
make test-integration   # includes TestE2EMultiShareUnsealHTTP
```

## Related

- Seal/unseal recipe: [seal-and-unseal.md](../recipes/seal-and-unseal.md)  
- W53 features: [formal-w53-residual-features-2026-07-16.md](../audit/formal-w53-residual-features-2026-07-16.md)  
- Testing guide: [testing.md](testing.md)  
