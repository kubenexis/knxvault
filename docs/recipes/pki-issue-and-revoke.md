# Recipe: PKI issue and revoke certificates

Create a root CA, issue leaf certificates, and revoke them with CRL publication.

## Prerequisites

- Admin token with `pki` capabilities

```bash
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=<admin-token>
```

## Create root CA

```bash
curl -s -X POST "$KNXVAULT_ADDR/pki/root" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "corp-root",
    "common_name": "Corp Root CA",
    "ttl": "8760h",
    "key_type": "rsa",
    "key_bits": 4096
  }' | jq .
```

## Issue leaf certificate

```bash
curl -s -X POST "$KNXVAULT_ADDR/pki/issue" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "role": "corp-root",
    "common_name": "api.example.com",
    "dns_names": ["api.example.com", "www.example.com"],
    "ttl": "720h",
    "auto_renew": true
  }' | jq . > leaf.json

jq -r .cert_pem leaf.json > leaf.crt
jq -r .private_key_pem leaf.json > leaf.key
SERIAL=$(jq -r .serial leaf.json)
```

## Export CA for trust bundle

```bash
CA_ID=$(curl -s "$KNXVAULT_ADDR/pki/ca/corp-root" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r .id)

curl -s "$KNXVAULT_ADDR/pki/ca/$CA_ID/export" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r .cert_pem > corp-root.crt

openssl verify -CAfile corp-root.crt leaf.crt
```

## Revoke and fetch CRL

```bash
curl -s -X POST "$KNXVAULT_ADDR/pki/revoke" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"ca_id\":\"$CA_ID\",\"serial\":\"$SERIAL\",\"reason\":\"keyCompromise\"}"

curl -s "$KNXVAULT_ADDR/pki/crl/$CA_ID" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r .crl_pem \
  | openssl crl -inform PEM -noout -text | grep -F "$SERIAL"
```

## Intermediate CA

See [PKI administration](../operations/pki-administration.md) and recipe extensions in manual tests MT-25.

## Related recipes

- [cert-manager integration](cert-manager-integration.md)
- [RBAC policies](rbac-policies.md)

## See also

- [PKI administration](../operations/pki-administration.md)