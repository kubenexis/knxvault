<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Contributing

Guidelines for submitting changes to KNXVault.

## Non-negotiable principles (read first)

Product and security rules that **must not** be violated for convenience or demos. Full text for humans **and** coding agents: **[`AGENTS.md`](../../AGENTS.md)** (N1–N5).

| ID | Principle (summary) |
|----|---------------------|
| **N1** | Core security over feature surface on the **custody** plane (master/unseal) |
| **N2** | **Instances** over mega-vault / in-process multi-tenant SaaS isolation |
| **N3** | Add-ons (operator/CSI/ESO/webhook) are **clients**, not co-custodians |
| **N4** | Do **not** micro-split the sealed core or add in-process untrusted plugins |
| **N5** | Default install = **base only**; feature gates fail closed; no CLI in server image |

Design: [distributed-trust-platform.md](../design/distributed-trust-platform.md).  
Agents must **immediately highlight** any request or change that trips these principles and propose a compliant alternative (see AGENTS.md response template).

## Before you start

1. Confirm the change does **not** violate **N1–N5** ([`AGENTS.md`](../../AGENTS.md)); if it might, stop and redesign or write an ADR
2. Check [backlog](../backlog.md) for planned work — avoid duplicating in-progress items
3. For significant design changes, write an [ADR](../adr/README.md) first
4. Ensure new dependencies pass the [licensing policy](../licensing.md)
5. Review dual licensing: **Apache-2.0** (code), **CC-BY-4.0** (docs) — CNCF Charter §11

## Developer Certificate of Origin (DCO)

Per CNCF Charter §11, every commit must be signed off with the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "feat(area): description"
```

The `-s` flag adds a `Signed-off-by: Your Name <email@example.com>` trailer. Configure `user.name` and `user.email` before committing.

By signing off, you certify that you have the right to submit the work under the project’s licenses (**Apache-2.0** for code, **CC-BY-4.0** for documentation).

## License headers

New or modified **source** files need:

```go
// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0
```

New or modified **documentation** (Markdown under `docs/`, README):

```markdown
<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->
```

```bash
bash scripts/ensure-license-headers.sh   # apply missing headers
make license-headers-check               # CI gate
```

## Development workflow

```bash
git checkout -b feat/my-feature
make all    # must pass before PR
git commit -s -m "feat(area): description"
```

Commit message format: [Conventional Commits](https://www.conventionalcommits.org/)

- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `test:` — test additions
- `chore:` — tooling, CI

## Pull request checklist

- [ ] **DTP N1–N5 respected** ([`AGENTS.md`](../../AGENTS.md)): no expansion of production/base default surface with CSI/ESO/webhook/ACME; no operator root/custody Secret get; no sealed-core microservice/plugin split without ADR
- [ ] `make all` passes (fmt, vet, lint, docs-lint, dtp-surface, gosec, licenses, license-headers-check, scan, test, integration, build)
- [ ] Commits are DCO signed (`Signed-off-by`)
- [ ] New code has unit tests and Apache-2.0 SPDX headers
- [ ] Documentation updates use CC-BY-4.0 SPDX headers
- [ ] API changes update `api/openapi.yaml`
- [ ] New env vars documented in [configuration reference](../installation/configuration.md)
- [ ] User-facing behavior documented in relevant `docs/` guide
- [ ] No copyleft dependencies introduced (run `make licenses`)
- [ ] ADR added for architectural decisions
- [ ] Security findings tagged `base` vs `addon:*` when applicable

## Code standards

- Match existing naming, import style, and error handling (`internal/domain/common/errors.go`)
- Keep handlers thin — delegate to services
- Domain models must not import infrastructure packages
- PKI issuance only through native Go `crypto/x509` (`internal/crypto/x509native`, `internal/crypto/pki`)
- Repository interfaces in `internal/repository/interfaces.go` — implementations in `dragonboat/` or `memory/`

## License

- **Code contributions** are licensed under [Apache-2.0](../../LICENSE).
- **Documentation contributions** are licensed under [CC-BY-4.0](../LICENSE).
- Full policy: [licensing.md](../licensing.md). You must have the right to submit your changes under these terms.

## Security issues

Do not open public issues for security vulnerabilities. Report privately to the maintainers.

## Related documents

- [**AGENTS.md** — non-negotiable principles N1–N5](../../AGENTS.md) (humans + AI agents)
- [Distributed Trust Platform](../design/distributed-trust-platform.md)
- [Development guide](development.md)
- [Extensibility / plugins](extensibility.md) — engines, façades, DNS-01 webhooks
- [Testing guide](testing.md)
- [Licensing policy](../licensing.md)
