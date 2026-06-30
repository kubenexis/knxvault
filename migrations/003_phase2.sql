-- Phase 2: dynamic secrets leases, persisted RBAC, database credential roles

CREATE TABLE IF NOT EXISTS leases (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    role_name TEXT NOT NULL,
    engine TEXT NOT NULL DEFAULT 'database',
    ttl_seconds INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    renewable BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_leases_expires_at ON leases (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY,
    policies JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS database_roles (
    name TEXT PRIMARY KEY,
    ttl_seconds INT NOT NULL DEFAULT 3600,
    username_prefix TEXT NOT NULL DEFAULT 'v-',
    default_username TEXT,
    creation_statements JSONB NOT NULL DEFAULT '[]'::jsonb,
    revocation_statements JSONB NOT NULL DEFAULT '[]'::jsonb,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);