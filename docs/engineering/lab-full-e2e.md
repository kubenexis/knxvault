# Lab full E2E — e2e-test01 (192.168.137.131)

| Field | Value |
|-------|-------|
| **Result** | **PASS** (38 / 38 checks) |
| **Date (UTC)** | 2026-07-16T05:46:26Z |
| **Host** | `e2e-test01` (`192.168.137.131`) |
| **Binary** | `knxvault` / `knxvault-cli` / `knxvault-operator` **0.4.5** @ commit `67d546d` |
| **Mode** | Single-node Dragonboat Raft (host process) + operator against local API |
| **Script** | `scripts/lab-full-e2e.sh` |

## What it covers

| Section | Checks | Purpose |
|---------|--------|---------|
| **core** | 20 | CLI health/status/doctor, auth, PKI, KV redaction, metrics/openapi, env-only CLI |
| **vaultcompat** | 14 | cert-manager Vault profile: `/v1/sys/health`, AppRole register/login, sign (issue+CSR), custom mount, AppRole token sign |
| **operator** | 4 | ClusterIssuer Ready, Certificate serial+caId, TLS Secret + annotations |

## Re-run

```bash
cd /path/to/knxvault
bash scripts/lab-full-e2e.sh                 # default host 192.168.137.131
bash scripts/lab-full-e2e.sh 192.168.137.131
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
SUMMARY|PASS=38 FAIL=0
FULL LAB E2E PASS on 192.168.137.131 (commit 67d546d)
```

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

## Related

- Narrower operator-only: `scripts/lab-operator-e2e.sh`  
- Earlier core-only record: [lab-e2e-test01.md](lab-e2e-test01.md)  
- cert-manager recipe: [cert-manager-integration.md](../recipes/cert-manager-integration.md)  
- Integration harness: `test/integration/e2e_daemon_test.go`  
