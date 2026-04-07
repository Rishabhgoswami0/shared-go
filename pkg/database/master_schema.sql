-- =============================================================
-- master-db schema  (run this once against your master database)
-- =============================================================

-- The `tenants` table is the single source of truth for routing.
-- Each service reads this at request-time to find the tenant's DB DSN.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   TEXT        PRIMARY KEY,              -- e.g. "school-mumbai", "university-delhi"
    write_dsn   TEXT        NOT NULL,                 -- postgres://user:pass@write-host:5432/tenant_db1
    read_dsn    TEXT        NOT NULL,                 -- postgres://user:pass@read-host:5432/tenant_db1
    region      TEXT        NOT NULL DEFAULT 'default',
    status      TEXT        NOT NULL DEFAULT 'active' -- 'active' | 'suspended' | 'deleted'
        CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast status filtering (e.g. fetch all active tenants)
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);

-- Sample rows (replace DSNs with real values):
-- INSERT INTO tenants (tenant_id, write_dsn, read_dsn, region) VALUES
--   ('school-mumbai',
--    'postgres://app_user:secret@write-host:5432/tenant_db1?sslmode=require',
--    'postgres://app_user:secret@read-host:5432/tenant_db1?sslmode=require',
--    'ap-south-1'),
--   ('university-delhi',
--    'postgres://app_user:secret@write-host:5432/tenant_db2?sslmode=require',
--    'postgres://app_user:secret@read-host:5432/tenant_db2?sslmode=require',
--    'ap-south-1');
