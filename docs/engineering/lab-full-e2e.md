# Lab full E2E — e2e-test01 (192.168.137.131)

| Field | Value |
|-------|-------|
| **Result** | **PASS** (44 / 44 checks) |
| **Date (UTC)** | 2026-07-16T08:27:16Z |
| **Host** | `e2e-test01` (`192.168.137.131`) |
| **Binary** | `knxvault` / `knxvault-cli` / `knxvault-operator` **0.4.5** (commit `eac59e9`+) |
| **Mode** | Single-node Dragonboat Raft (host process) + operator against local API |
| **Script** | `scripts/lab-full-e2e.sh` |

## What it covers

| Section | Checks | Purpose |
|---------|--------|---------|
| **core** | 23 | CLI health/status/doctor, auth, PKI, KV redaction, metrics/openapi, env-only CLI, **W53 generate-unseal-shares** |
| **vaultcompat** | 14 | Vault product profile: health, AppRole, sign (issue+CSR), custom mount |
| **operator** | 4 | Vault-mode ClusterIssuer Ready, Certificate serial+caId, TLS Secret |
| **multi-issuer** | 3 | SelfSigned ClusterIssuer + Certificate + Secret (no cert-manager) |

## Unseal (required)

With Raft, `KNXVAULT_UNSEAL_KEY` is set and the process **starts sealed** (W50-03 / W52). The lab script:

1. Starts `knxvault serve` with distinct master + unseal keys  
2. Waits for `/ready`  
3. **`POST /sys/unseal`** with the unseal key (`UNSEAL_OK`) before operator start and checks  

Without step 3, data-plane and operator vault-mode checks fail with `unavailable: vault is sealed`.

## Re-run

```bash
cd /path/to/knxvault
bash scripts/lab-full-e2e.sh                 # default host 192.168.137.131
bash scripts/lab-full-e2e.sh 192.168.137.131
# or
make lab-full-e2e
```

Requires: SSH as `root` to the lab host, `kubectl` on the host, OpenSSL, `make build build-cli build-operator` on the build machine.

Artifacts on the lab node:

| Path | Purpose |
|------|---------|
| `/opt/knxvault/knxvault{,-cli,-operator}` | Binaries under test |
| `/var/lib/knxvault/raft-full` | Fresh Raft data dir for this run |
| `/var/log/knxvault/full-e2e-serve.log` | Server log |
| `/var/log/knxvault/full-e2e-operator.log` | Operator log |
| `/opt/knxvault/e2e-full-results.txt` | Last check transcript |

## Last run summary

```
SUMMARY|PASS=44 FAIL=0
FULL LAB E2E PASS on 192.168.137.131 (commit eac59e9)
```

### W53 checks (core)

- `POST /sys/generate-unseal-shares` → `shares` + `threshold: 2`  
- Health remains unsealed after share split API  

### vaultcompat highlights

- `GET /v1/sys/health` → 200, initialized, unsealed  
- `POST /sys/auth/approle` + `POST /v1/auth/approle/login` → client_token  
- `POST /v1/pki/sign/web-server` with `X-Vault-Token` (issue + CSR)  
- `POST /v1/pki_int/sign/web-server` (custom mount)  
- AppRole-issued token can sign  

### operator highlights

- `KNXVaultClusterIssuer/platform` Ready=True  
- `KNXVaultCertificate/app-tls` has serial + caId  
- Kubernetes Secret `app-tls` created with annotations  

## Local integration E2E (same machine)

```bash
make test-integration   # includes TestE2E* daemon CLI + W53 HTTP tests
```

| Test | Coverage |
|------|----------|
| `TestE2EDaemonCLIWorkflow` | health, doctor, PKI, KV redaction (auto-unseal after start) |
| `TestE2EMultiShareUnsealHTTP` | Shamir share submit until unsealed |
| `TestE2ETenantPKIScopesCANames` | tenant mode namespace required + PKI under tenant |
| `TestE2ECertLoginHTTP` | client-cert auth method (`LoginWithClientCert`) |

## Related

- Narrower operator-only: `scripts/lab-operator-e2e.sh`  
- Earlier core-only record: [lab-e2e-test01.md](lab-e2e-test01.md)  
- cert-manager recipe: [cert-manager-integration.md](../recipes/cert-manager-integration.md)  
- Seal/unseal recipe: [seal-and-unseal.md](../recipes/seal-and-unseal.md)  
- W53 features: [formal-w53-residual-features-2026-07-16.md](../audit/formal-w53-residual-features-2026-07-16.md)  
- Integration harness: `test/integration/e2e_daemon_test.go`, `w53_e2e_test.go`  
