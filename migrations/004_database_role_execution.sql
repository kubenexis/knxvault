-- Database role execution metadata (legacy PostgreSQL backend).
ALTER TABLE database_roles
    ADD COLUMN IF NOT EXISTS execution_mode TEXT NOT NULL DEFAULT 'client';

ALTER TABLE database_roles
    ADD COLUMN IF NOT EXISTS admin_credentials_path TEXT;