<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Identity entities and groups (M-IDENT-1)

Map multiple auth methods to one logical identity and attach group policies.

## Create entity and alias

```bash
# Entity
curl -sS -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"alice","policies":["reader"]}' \
  "$KNXVAULT_ADDR/identity/entity"
# → {"id":"ent_...","name":"alice",...}

# Alias (OIDC subject)
curl -sS -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"entity_id":"ent_...","mount":"oidc","name":"alice@example.com"}' \
  "$KNXVAULT_ADDR/identity/alias"
```

## Group policies

```bash
curl -sS -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"platform-admins","member_entity_ids":["ent_..."],"policies":["admin"]}' \
  "$KNXVAULT_ADDR/identity/group"
```

On login via a mount that resolves the alias, knxvault merges **role policies + entity policies + group policies**.

## Disable entity

```bash
curl -sS -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"disabled":true}' \
  "$KNXVAULT_ADDR/identity/entity/ent_.../disable"
```

## Permissions

`identity` **sudo** for create/disable; `identity` **read** for list/get.

## Notes

- Identity snapshot is **sealed in storage** at `sys/internal/identity` (W74-05) when crypto+secret repo are available (Raft-backed in production).  
- Policy names on entities/groups are validated against the policy repository when wired (unknown policy rejected).  
- LDAP login already uses `ResolveLogin` for `mount=ldap` aliases.
