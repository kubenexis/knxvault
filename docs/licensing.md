<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# KNXVault — Licensing Policy

This project follows the **CNCF Charter §11 IP Policy** (default mode):

| Content | SPDX license | Where |
| ------- | ------------ | ----- |
| **Source code** and software artifacts | **Apache-2.0** | Repository root [`LICENSE`](../LICENSE), [`LICENSES/Apache-2.0.txt`](../LICENSES/Apache-2.0.txt) |
| **Documentation** | **CC-BY-4.0** | [`docs/LICENSE`](LICENSE), [`LICENSES/CC-BY-4.0.txt`](../LICENSES/CC-BY-4.0.txt) |

Attribution / Apache NOTICE: [`NOTICE`](../NOTICE).

Machine-readable path annotations: [`REUSE.toml`](../REUSE.toml) ([REUSE Specification](https://reuse.software/spec/)).

## CNCF alignment

Under the [CNCF Charter](https://github.com/cncf/foundation/blob/main/charter.md) §11 (IP Policy):

- **Outbound code** is Apache License, Version 2.0.
- **Documentation** is received and made available under Creative Commons Attribution 4.0 International (CC-BY-4.0).
- **Inbound contributions**: Developer Certificate of Origin (DCO) sign-off (`Signed-off-by`) on commits, and code contributions under Apache-2.0.
- File-level notices follow [CNCF license notice guidance](https://github.com/cncf/foundation/blob/main/license-notices.md) (SPDX short-form identifiers and recommended copyright phrasing).
- Copyright notices use: **Copyright Kubenexis Systems Private Limited.** (CNCF permits project- or organization-specific notices; see [copyright notices guidance](https://github.com/cncf/foundation/blob/main/copyright-notices.md)).

### License notice format (required on files)

**Go / source (Apache-2.0):**

```go
// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0
```

**Documentation Markdown (CC-BY-4.0):**

```markdown
<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->
```

**Shell / Makefile / YAML (Apache-2.0):**

```
# Copyright Kubenexis Systems Private Limited.
# SPDX-License-Identifier: Apache-2.0
```

Apply or check headers:

```bash
bash scripts/ensure-license-headers.sh          # add missing headers
make license-headers-check                     # fail if any missing
```

## Project license texts

| File | Purpose |
| ---- | ------- |
| [`LICENSE`](../LICENSE) | Full Apache-2.0 text (primary outbound code license) |
| [`docs/LICENSE`](LICENSE) | CC-BY-4.0 notice for documentation |
| [`LICENSES/Apache-2.0.txt`](../LICENSES/Apache-2.0.txt) | Apache-2.0 (REUSE / redistributors) |
| [`LICENSES/CC-BY-4.0.txt`](../LICENSES/CC-BY-4.0.txt) | Full CC-BY-4.0 legal code |
| [`NOTICE`](../NOTICE) | Apache-2.0 attribution NOTICE |
| [`REUSE.toml`](../REUSE.toml) | Path-based SPDX annotations |

## Third-party dependency licenses (allow-list)

Direct and scanned module licenses must stay on the permissive allow-list (LLD §1.5). Preferred: **Apache-2.0**.

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

The machine-readable list is [`config/licenses.allow`](../config/licenses.allow).

### Deny-list (default deny)

- **Copyleft**: GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-*
- **Weak copyleft**: MPL-2.0 (exceptions require an ADR in `docs/adr/`)
- **Restrictive / non-standard**: proprietary, UNLICENSED, CDLA-*, OFL-* (except narrowly scoped font exceptions)

### Enforcement

1. **Local / CI**: `make licenses` runs `scripts/check-licenses.sh` (module license scanner; SPDX allow-list in `config/licenses.allow`).
2. **Headers**: `make license-headers-check` (SPDX on project sources and docs).
3. **PR gate**: `make quality` / `make all` include license checks.
4. **Containers**: Trivy vulnerability scan (`make scan`); license exceptions documented below.
5. **Exceptions**: record under [Exceptions](#exceptions) with rationale and ADR link.

### Adding a dependency

1. Confirm SPDX license against the allow-list.
2. Run `make licenses` before opening a PR.
3. If the license is not on the allow-list, stop — find an Apache-2.0/MIT alternative.

### Exceptions

| Module | License | Rationale | ADR |
| ------ | ------- | --------- | --- |
| `github.com/lni/dragonboat/v3` (+ transitive Hashicorp/MPL, juju/LGPL) | MPL-2.0, LGPL-3.0 | Embedded Raft storage backend (Phase 3); static Go linking only. | W23-01 |
| `github.com/pkg/errors` | BSD-2-Clause | Dragonboat transitive; no LICENSE file in module root (Dave Cheney, 2015). | W23-01 |
| `github.com/magiconair/properties` | BSD-2-Clause | Viper transitive; license in `LICENSE.md` (Frank Schroeder). | W38-13 |

### OpenSSL

Production images use distro OpenSSL 3.x packages with Apache-compatible linkage. No GPL-only OpenSSL builds in production artifacts.

## What is “code” vs “documentation”?

| Category | Examples | License |
| -------- | -------- | ------- |
| Code / software | `cmd/`, `internal/`, `pkg/`, `api/`, `scripts/`, `deployments/`, `config/`, Dockerfiles, Makefile, Go modules | Apache-2.0 |
| Documentation | `docs/**/*.md`, project `README.md`, contributing/security prose | CC-BY-4.0 |

Generated client SDKs under `clients/` are software and use **Apache-2.0**.

## Contributor obligations

1. Sign off every commit (**DCO**): `git commit -s`.
2. New **code** is contributed under **Apache-2.0**.
3. New **documentation** is contributed under **CC-BY-4.0**.
4. Do not introduce copyleft **direct** dependencies without a written exception and ADR.
5. Preserve third-party copyright and license notices when reusing external files ([CNCF guidance](https://github.com/cncf/foundation/blob/main/license-notices.md)).
