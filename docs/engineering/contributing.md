# Contributing

Guidelines for submitting changes to KNXVault.

## Before you start

1. Check [backlog](../backlog.md) for planned work — avoid duplicating in-progress items
2. For significant design changes, write an [ADR](../adr/README.md) first
3. Ensure new dependencies pass the [licensing policy](../licensing.md)

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

- [ ] `make all` passes (fmt, vet, lint, gosec, licenses, scan, test, integration, build)
- [ ] New code has unit tests
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

Contributions are licensed under [Apache-2.0](../../LICENSE). You must have the right to submit your changes.

## Security issues

Do not open public issues for security vulnerabilities. Report privately to the maintainers.

## Related documents

- [Development guide](development.md)
- [Extensibility / plugins](extensibility.md) — engines, façades, DNS-01 webhooks
- [Testing guide](testing.md)
- [Licensing policy](../licensing.md)