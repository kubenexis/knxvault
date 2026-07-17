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

- Store is process-local (in-memory) in this release; plan Raft-backed identity store for multi-node HA of identity objects.  
- Wire OIDC/K8s login to call `ResolveLogin` when aliases exist (LDAP already hooks the resolver).
