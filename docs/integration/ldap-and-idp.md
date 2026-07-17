# LDAP and IdP authentication (W70)

## Preferred: directory → IdP → OIDC

Most production platforms should:

1. Keep users/groups in LDAP/AD.  
2. Federate with Keycloak, Authentik, Azure AD, Okta, etc.  
3. Use knxvault **`POST /auth/oidc/:role`** (already shipped).

See [OIDC recipe](../recipes/oidc-authentication.md).

## Native LDAP bind (optional)

When no IdP is available. **Server-side configuration only (W74-01)** — request headers **cannot** set LDAP URL, DN template, or TLS skip.

### Configure server

```bash
export KNXVAULT_LDAP_URL="ldaps://ldap.example.com:636"
export KNXVAULT_LDAP_USER_DN_TEMPLATE="uid=%s,ou=people,dc=example,dc=com"
export KNXVAULT_LDAP_DEFAULT_POLICIES="reader,dev"
# Lab only (rejected when KNXVAULT_SECURITY_PROFILE=production):
# export KNXVAULT_LDAP_INSECURE_SKIP_VERIFY=true
```

If `KNXVAULT_LDAP_URL` is unset, `POST /auth/ldap` returns **unavailable** (method disabled).

### Login

```bash
curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"..."}' \
  "$KNXVAULT_ADDR/auth/ldap"
```

### Behavior

- Simple Bind as the user DN (template with exactly one `%s` = username).  
- Usernames must match allowlist `[a-zA-Z0-9._@+-]{1,128}` (blocks DN/filter injection).  
- BindResponse is parsed structurally (resultCode == success); not a byte-scan.  
- Default policies from **env only**; identity service may merge entity/group policies (`mount=ldap`).  
- Login lockout and audit apply.  
- Production profile requires **`ldaps://`** and forbids insecure skip verify.

### Limits

- No full LDAP group search/sync in this release (use identity groups or default policies).  
- Prefer IdP → OIDC for production directories.
