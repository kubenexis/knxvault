# LDAP and IdP authentication (W70)

## Preferred: directory → IdP → OIDC

Most production platforms should:

1. Keep users/groups in LDAP/AD.  
2. Federate with Keycloak, Authentik, Azure AD, Okta, etc.  
3. Use knxvault **`POST /auth/oidc/:role`** (already shipped).

See [OIDC recipe](../recipes/oidc-authentication.md).

## Native LDAP bind (optional)

When no IdP is available:

### Configure server

```bash
export KNXVAULT_LDAP_URL="ldaps://ldap.example.com:636"
export KNXVAULT_LDAP_USER_DN_TEMPLATE="uid=%s,ou=people,dc=example,dc=com"
export KNXVAULT_LDAP_DEFAULT_POLICIES="reader,dev"
# Lab only:
# export KNXVAULT_LDAP_INSECURE_SKIP_VERIFY=true
```

### Login

```bash
curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"..."}' \
  "$KNXVAULT_ADDR/auth/ldap"
```

### Behavior

- Simple Bind as the user DN (template with `%s` = username).  
- Default policies from env; identity service can merge group/entity policies when aliases exist (`mount=ldap`).  
- Login lockout and audit (`auth.login` / failed) apply.  
- Binder is injectable for tests; production uses TCP/TLS Simple Bind.

### Limits

- No full LDAP group search/sync in this release (map policies via identity groups or default policies).  
- Prefer ldaps://; insecure skip verify is lab-only.  
- Production security profile still forbids other lab auth flags (JWT secret, k8s insecure).
