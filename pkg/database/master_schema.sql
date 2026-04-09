-- =============================================================
-- master-db schema  (run this once against your master database)
-- =============================================================

-- The `tenants` table is the single source of truth for routing.
-- Each service reads this at request-time to find the tenant's DB DSN.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id          TEXT        PRIMARY KEY,     
    db_write_host      TEXT        NOT NULL,
    db_write_port      TEXT        NOT NULL,
    db_write_name      TEXT        NOT NULL,
    db_write_user      TEXT        NOT NULL,
    db_write_password  TEXT        NOT NULL,
    db_read_host       TEXT        NOT NULL,
    db_read_port       TEXT        NOT NULL,
    db_read_name       TEXT        NOT NULL,
    db_read_user       TEXT        NOT NULL,
    db_read_password   TEXT        NOT NULL,
    region             TEXT        NOT NULL DEFAULT 'default',
    status             TEXT        NOT NULL DEFAULT 'active' 
        CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast status filtering (e.g. fetch all active tenants)
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);

-- Sample rows (replace DSNs with real values):
-- INSERT INTO tenants (tenant_id, db_write_host, db_write_port, db_write_name, db_write_user, db_write_password, db_read_host, db_read_port, db_read_name, db_read_user, db_read_password, region) VALUES
--   ('school-mumbai',
--    'write-host', '5432', 'tenant_db1', 'app_user', 'secret',
--    'read-host', '5432', 'tenant_db1', 'app_user', 'secret',
--    'ap-south-1');
