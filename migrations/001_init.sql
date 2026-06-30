-- KNXVault initial schema (LLD §4.D.1)

CREATE TABLE IF NOT EXISTS cas (
    id UUID PRIMARY KEY,
    parent_id UUID REFERENCES cas(id) ON DELETE RESTRICT,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL CHECK (type IN ('root', 'intermediate')),
    cert_pem TEXT NOT NULL,
    privkey_enc BYTEA NOT NULL,
    dek_enc BYTEA NOT NULL,
    serial TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    crl_next_update TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cas_parent_id ON cas(parent_id);

CREATE TABLE IF NOT EXISTS secret_versions (
    id UUID PRIMARY KEY,
    path TEXT NOT NULL,
    version INT NOT NULL,
    data_enc BYTEA NOT NULL,
    dek_enc BYTEA NOT NULL,
    lease_id TEXT,
    ttl_seconds INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    destroyed BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(path, version)
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_path ON secret_versions(path);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    entry_hash TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);