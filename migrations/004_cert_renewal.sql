-- Phase 2 W16: issued certificate tracking for renewal automation

CREATE TABLE IF NOT EXISTS issued_certificates (
    id UUID PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES cas(id) ON DELETE RESTRICT,
    role TEXT NOT NULL,
    serial TEXT NOT NULL,
    common_name TEXT NOT NULL,
    dns_names JSONB NOT NULL DEFAULT '[]'::jsonb,
    ttl_seconds INT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
    renewed_from_serial TEXT,
    UNIQUE (ca_id, serial)
);

CREATE INDEX IF NOT EXISTS idx_issued_certs_expires_at
    ON issued_certificates (expires_at)
    WHERE auto_renew = TRUE;