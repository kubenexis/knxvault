<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Contributing

Guidelines for submitting changes to KNXVault.

## Before you start

1. Check [backlog](../backlog.md) for planned work — avoid duplicating in-progress items
2. For significant design changes, write an [ADR](../adr/README.md) first
3. Ensure new dependencies pass the [licensing policy](../licensing.md)
4. Review dual licensing: **Apache-2.0** (code), **CC-BY-4.0** (docs) — CNCF Charter §11

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
// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0
```

New or modified **documentation** (Markdown under `docs/`, README):

```markdown
<!--
Copyright The KNXVault Authors.
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

- [ ] `make all` passes (fmt, vet, lint, docs-lint, gosec, licenses, license-headers-check, scan, test, integration, build)
- [ ] Commits are DCO signed (`Signed-off-by`)
- [ ] New code has unit tests and Apache-2.0 SPDX headers
- [ ] Documentation updates use CC-BY-4.0 SPDX headers
- [ ] API changes update `api/openapi.yaml`
- [ ] New env vars documented in [configuration reference](../installation/configuration.md)
- [ ] User-facing behavior documented in relevant `docs/` guide
- [ ] No copyleft dependencies introduced (run `make licenses`)
- [ ] ADR added for architectural decisions

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

- [Development guide](development.md)
- [Extensibility / plugins](extensibility.md) — engines, façades, DNS-01 webhooks
- [Testing guide](testing.md)
- [Licensing policy](../licensing.md)
