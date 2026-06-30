# KNXVault — Licensing Policy

KNXVault is released under **Apache-2.0**. This document defines the permissive-only dependency policy referenced in LLD §1.5.

## Allow-list (SPDX identifiers)

| License | Status |
| ------- | ------ |
| Apache-2.0 | Preferred |
| MIT | Allowed |
| BSD-2-Clause | Allowed |
| BSD-3-Clause | Allowed |
| ISC | Allowed |
| Unicode-3.0 | Allowed |
| 0BSD | Allowed |
| CC0-1.0 | Allowed |

The canonical machine-readable list lives in [`config/licenses.allow`](../config/licenses.allow).

## Deny-list (default deny)

- **Copyleft**: GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-*
- **Weak copyleft**: MPL-2.0 (exceptions require an ADR in `docs/adr/`)
- **Restrictive / non-standard**: proprietary, UNLICENSED, CDLA-*, OFL-* (except narrowly scoped font exceptions)

## Enforcement

1. **Local / CI**: `make licenses` runs `scripts/check-licenses.sh` (Go 1.25-compatible module license scanner; SPDX allow-list in `config/licenses.allow`).
2. **PR gate**: `make all` includes the license check.
3. **Containers**: scan images with Trivy license scanner (`make scan`).
4. **Exceptions**: record in this file under [Exceptions](#exceptions) with rationale and ADR link.

## Adding a dependency

1. Confirm SPDX license against the allow-list.
2. Run `make licenses` before opening a PR.
3. If the license is not on the allow-list, stop — find an Apache-2.0/MIT alternative.

## Exceptions

| Module | License | Rationale | ADR |
| ------ | ------- | --------- | --- |
| `github.com/lni/dragonboat/v3` (+ transitive Hashicorp/MPL, juju/LGPL) | MPL-2.0, LGPL-3.0 | Embedded Raft storage backend (Phase 3); static Go linking only. | W23-01 |
| `github.com/pkg/errors` | BSD-2-Clause | Dragonboat transitive; no LICENSE file in module root (Dave Cheney, 2015). | W23-01 |
| `github.com/magiconair/properties` | BSD-2-Clause | Viper transitive; license in `LICENSE.md` (Frank Schroeder). | W38-13 |

## OpenSSL

Production images use distro OpenSSL 3.x packages with Apache-compatible linkage. No GPL-only OpenSSL builds in production artifacts.