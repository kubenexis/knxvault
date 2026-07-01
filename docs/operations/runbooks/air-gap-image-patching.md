# Air-gap OpenSSL CVE patching runbook

This runbook covers immutable-container OpenSSL patching for regulated air-gap deployments (**W41-12**).

## Prerequisites

- Access to a connected build host with Docker and `make`
- Air-gap registry mirror
- Current KNXVault SBOM (`sbom.json`) baseline

## Procedure

1. **Monitor advisories** — Subscribe to [Debian security announcements](https://www.debian.org/security/) for bookworm OpenSSL 3.x CVEs.
2. **Rebuild base image** — Pull an updated `debian:bookworm-slim` digest and run `make docker-build`.
3. **Generate artifacts** — Run `make sbom` and `make scan`; archive SBOM diff against the previous release.
4. **Sign and transfer** — Sign the image manifest; push to the air-gap registry per your change-control process.
5. **Pre-update backup** — On each replica, `POST /sys/backup` before rollout (leader only).
6. **Rolling update** — Apply `kubectl rollout restart statefulset/knxvault -n knxvault`; verify `/ready` and Raft leader.
7. **Post-verify** — `knxvault-cli doctor --json`; optionally `kubectl exec` and run `openssl version` until **W41-10** native-only images remove the binary.

## CVE response SLA template

| Severity | Triage | Patch image | Customer notification |
|----------|--------|-------------|------------------------|
| Critical | 4 h | 24 h | Same day |
| High | 1 business day | 3 business days | Within 48 h |
| Medium | 3 business days | Next maintenance window | Release notes |

## SBOM diff checklist

- [ ] OpenSSL package version changed in `sbom.json`
- [ ] No new denied SPDX licenses (`make licenses`)
- [ ] Trivy scan clean or documented waivers
- [ ] Integration tests green on rebuilt image

## Related

- [PKI OpenSSL migration](../pki-openssl-migration.md) — eliminate OpenSSL subprocess with `KNXVAULT_PKI_BACKEND=native`
- [PoC evaluation guide](../../product/poc-evaluation-guide.md)