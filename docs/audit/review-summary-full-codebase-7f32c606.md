# Review Summary — Full KNXVault Codebase

- **Mode**: full-codebase multi-pass (not diff-only)
- **Target**: entire knxvault tree @ 5242c30
- **Review ID**: 7f32c606
- **Packages**: ~75 Go packages; ~455 .go files
- **go test ./...**: PASS
- **Issue counts (review skill full)**: 11 bugs, 23 suggestions, 2 nits (36)
- **Issue counts (security deep dive)**: 8 bugs, 6 suggestions, 2 nits (16)
- **Formal 10-cycle**: complete

## Top issues
1. [bug] ESO /fetch unauthenticated + SA auto-login
2. [bug] Mutating webhook plaintext HTTP + Fail policy
3. [bug] Seal allows secret GETs; seal not durable
4. [bug] AppRole/init not Raft-replicated
5. [bug] Server SA missing TokenReview RBAC

## Artifacts
- docs/audit/formal-10cycle-full-codebase-2026-07-16.md
- docs/audit/review-skill-full-codebase-7f32c606.md
- docs/audit/review-skill-security-deep-dive-7f32c606.md
