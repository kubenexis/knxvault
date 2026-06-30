-- Revoked certificate tracking (LLD §4.A.3)

CREATE TABLE IF NOT EXISTS revoked_certificates (
    serial TEXT PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT NOT NULL DEFAULT 'unspecified'
);

CREATE INDEX IF NOT EXISTS idx_revoked_certificates_ca_id ON revoked_certificates(ca_id);