package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Rishabhgoswami0/shared-go/pkg/crypto"
	"github.com/Rishabhgoswami0/shared-go/pkg/database/postgres"
)

// ─── Errors ────────────────────────────────────────────────────────────────

var (
	// ErrTenantNotFound is returned when the tenant_id has no record in master-db.
	ErrTenantNotFound = errors.New("tenant not found")

	// ErrTenantInactive is returned when the tenant exists but is not in "active" status.
	ErrTenantInactive = errors.New("tenant is inactive")

	// ErrConfigurationMissing is returned when no DSN configuration exists for the requested service.
	ErrConfigurationMissing = errors.New("tenant database configuration missing for this service")
)

// TenantDBConfig isolates credentials and network details for a database
type TenantDBConfig struct {
	Host     string
	Port     string
	Name     string
	User     string
	Password string // Extracted from DB, decrypted in memory
}

// TenantRecord mirrors a tenant's connection configuration.
type TenantRecord struct {
	TenantID string
	WriteDB  TenantDBConfig
	ReadDB   TenantDBConfig
	Region   string
	Status   string

	// Dynamically generated after decryption
	WriteDSN string
	ReadDSN  string
}

type cachedRecord struct {
	record    *TenantRecord
	expiresAt time.Time
}

// ─── TenantConnPair ────────────────────────────────────────────────────────

// TenantConnPair holds the write and read DB pools for a single tenant.
type TenantConnPair struct {
	Write    *sql.DB
	Read     *sql.DB
	lastUsed time.Time
}

// ─── PoolConfig ────────────────────────────────────────────────────────────

// PoolConfig controls connection-pool settings applied to every tenant DB opened.
type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	// IdleTTL is how long a tenant pool can sit unused before being evicted.
	IdleTTL time.Duration
	// EnableReadReplica determines whether a separate Read connection is opened per tenant.
	// When false (dev default), Read points to the same pool as Write (no replica needed).
	// [PRODUCTION] Set to true once read replicas are provisioned per tenant.
	EnableReadReplica bool
}

// DefaultPoolConfig returns sensible production defaults.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxOpenConns:    100,
		MaxIdleConns:    20,
		ConnMaxLifetime: 5 * time.Minute,
		IdleTTL:         30 * time.Minute,
		EnableReadReplica: false,
	}
}

// ─── TenantDBPool ──────────────────────────────────────────────────────────

// TenantDBPool manages a lazily-loaded, TTL-evicted map of per-tenant DB connection pairs.
//
// DSNs stored in master-db are AES-256-GCM encrypted. The pool decrypts them
// transparently at lookup time using the encryptionKey provided at construction.
//
// Usage pattern:
//
//	pool := database.NewTenantDBPool(masterDB.Read, cfg, encryptionKey)
//	pair, err := pool.Get(ctx, tenantID)
//	pair.Write.Exec(...)   // mutations
//	pair.Read.QueryRow(...)  // reads
type TenantDBPool struct {
	masterRead    *sql.DB // used to lookup tenant DSNs
	cfg           PoolConfig
	encryptionKey string // AES-256-GCM key (raw string, derived via SHA-256)
	mu            sync.RWMutex
	pools         map[string]*TenantConnPair
	
	// Cache for Master DB lookups (Phase 2)
	lookupMu      sync.RWMutex
	lookupEntries map[string]*cachedRecord // key: tenantID + ":" + serviceCode
	lookupTTL     time.Duration

	stopCh        chan struct{}
}

// NewTenantDBPool creates a pool manager and starts the background idle-evictor.
//
//   - masterRead: *sql.DB pointing at the master-db READ replica.
//   - cfg: connection pool settings applied to every tenant DB.
//   - encryptionKey: the raw string value of DSN_ENCRYPTION_KEY env var.
//     DSNs in master-db must have been encrypted with database.EncryptDSN() using the same key.
func NewTenantDBPool(masterRead *sql.DB, cfg PoolConfig, encryptionKey string) *TenantDBPool {
	if encryptionKey == "" {
		panic("NewTenantDBPool: encryptionKey must not be empty — set DSN_ENCRYPTION_KEY env var")
	}
	p := &TenantDBPool{
		masterRead:    masterRead,
		cfg:           cfg,
		encryptionKey: encryptionKey,
		pools:         make(map[string]*TenantConnPair),
		lookupEntries: make(map[string]*cachedRecord),
		lookupTTL:     5 * time.Minute, // Standard Phase 2 TTL
		stopCh:        make(chan struct{}),
	}
	go p.startEviction()
	return p
}

// Get returns the TenantConnPair for the given tenantID.
//   - On first call for a tenant: looks up DSNs in master-db, opens connections, caches.
//   - On subsequent calls: returns the cached pair (fast path, read-lock only).
//   - Returns ErrTenantNotFound if no row exists in master-db.
//   - Returns ErrTenantInactive if the tenant is suspended/deleted.
func (p *TenantDBPool) Get(ctx context.Context, tenantID, serviceCode string) (*TenantConnPair, error) {
	log.Printf("[TenantDBPool] GET called for tenant: %s service: %s", tenantID, serviceCode)
	// ── Fast path: already cached connection ──────────────────────────────
	p.mu.RLock()
	if pair, ok := p.pools[tenantID]; ok {
		pair.lastUsed = time.Now()
		p.mu.RUnlock()
		return pair, nil
	}
	p.mu.RUnlock()

	// ── Mid path: lookup cache ───────────────────────────────────────────
	cacheKey := tenantID + ":" + serviceCode
	p.lookupMu.RLock()
	entry, ok := p.lookupEntries[cacheKey]
	p.lookupMu.RUnlock()

	var record *TenantRecord
	var err error

	if ok && time.Now().Before(entry.expiresAt) {
		record = entry.record
	} else {
		// ── Slow path: load from master-db ─────────────────────────────────────
		log.Printf("[TenantDBPool] Lookup cache MISS for %s", cacheKey)
		record, err = p.lookupTenant(ctx, tenantID, serviceCode)
		if err != nil {
			return nil, err
		}
		
		// Update lookup cache
		p.lookupMu.Lock()
		p.lookupEntries[cacheKey] = &cachedRecord{
			record:    record,
			expiresAt: time.Now().Add(p.lookupTTL),
		}
		p.lookupMu.Unlock()
	}

	pair, err := p.openTenantConnections(record)
	if err != nil {
		return nil, fmt.Errorf("tenant %q: failed to open connections: %w", tenantID, err)
	}

	// ── Write into cache ───────────────────────────────────────────────────
	p.mu.Lock()
	// Double-check: another goroutine may have populated while we were connecting.
	if existing, ok := p.pools[tenantID]; ok {
		// Close the duplicate we just opened and return the winner.
		pair.Write.Close()
		pair.Read.Close()
		p.mu.Unlock()
		return existing, nil
	}
	p.pools[tenantID] = pair
	log.Println("STEP 3H: Tenant cached:", tenantID)
	p.mu.Unlock()

	log.Printf("[TenantDBPool] loaded tenant %q (region=%s)", tenantID, record.Region)
	return pair, nil
}

// Remove evicts a specific tenant from the cache and closes its connections.
// Use this if you know a tenant's DSN has changed (e.g. after credential rotation).
func (p *TenantDBPool) Remove(tenantID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pair, ok := p.pools[tenantID]; ok {
		pair.Write.Close()
		pair.Read.Close()
		delete(p.pools, tenantID)
		log.Printf("[TenantDBPool] evicted tenant %q", tenantID)
	}
}

// Close shuts down all cached tenant pools and the background evictor goroutine.
// Call this during graceful server shutdown.
func (p *TenantDBPool) Close() {
	close(p.stopCh)

	p.mu.Lock()
	defer p.mu.Unlock()
	for id, pair := range p.pools {
		pair.Write.Close()
		pair.Read.Close()
		delete(p.pools, id)
	}
	log.Println("[TenantDBPool] all tenant connections closed")
}

// ─── internal helpers ──────────────────────────────────────────────────────

// lookupTenant queries the master-db read replica for the tenant's routing record
// and decrypts the DSNs using AES-256-GCM before returning.
func (p *TenantDBPool) lookupTenant(ctx context.Context, tenantID, serviceCode string) (*TenantRecord, error) {
	const q = `
		SELECT 
			t.id, 
			c.db_write_host, c.db_write_port, c.db_write_name, c.db_write_user, c.db_write_password,
			c.db_read_host, c.db_read_port, c.db_read_name, c.db_read_user, c.db_read_password,
			t.region, t.status
		FROM tenants t
		JOIN services s ON s.service_code = $2
		JOIN tenant_service_db_config c ON c.tenant_id = t.id AND c.service_id = s.id
		WHERE t.id = $1
		LIMIT 1
	`
	row := p.masterRead.QueryRowContext(ctx, q, tenantID, serviceCode)

	var rec TenantRecord
	if err := row.Scan(
		&rec.TenantID,
		&rec.WriteDB.Host, &rec.WriteDB.Port, &rec.WriteDB.Name, &rec.WriteDB.User, &rec.WriteDB.Password,
		&rec.ReadDB.Host, &rec.ReadDB.Port, &rec.ReadDB.Name, &rec.ReadDB.User, &rec.ReadDB.Password,
		&rec.Region, &rec.Status,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Check if tenant exists at all to return a better error
			var exists bool
			p.masterRead.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)", tenantID).Scan(&exists)
			if exists {
				return nil, ErrConfigurationMissing
			}
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("master-db lookup for tenant %q: %w", tenantID, err)
	}

	if rec.Status != "active" {
		return nil, fmt.Errorf("%w: tenant_id=%s status=%s", ErrTenantInactive, tenantID, rec.Status)
	}
	log.Println("STEP 3D: Tenant found and active:", tenantID)
	// ── Decrypt Passwords (AES-256-GCM) ────────────────────────────────────
	// Passwords are stored encrypted in master-db. Decrypt them now, in memory only.
	decWritePass, err := crypto.DecryptDSN(rec.WriteDB.Password, p.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("tenant %q: db_write_password decryption failed (wrong key or tampered data): %w", tenantID, err)
	}
	decReadPass, err := crypto.DecryptDSN(rec.ReadDB.Password, p.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("tenant %q: db_read_password decryption failed (wrong key or tampered data): %w", tenantID, err)
	}

	rec.WriteDB.Password = decWritePass
	rec.ReadDB.Password = decReadPass
	log.Println("STEP 3E: Password decrypted successfully for tenant:", tenantID)
	// Re-construct the full DSN strings dynamically for database/sql usage
	rec.WriteDSN = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		rec.WriteDB.User, rec.WriteDB.Password, rec.WriteDB.Host, rec.WriteDB.Port, rec.WriteDB.Name)

	rec.ReadDSN = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		rec.ReadDB.User, rec.ReadDB.Password, rec.ReadDB.Host, rec.ReadDB.Port, rec.ReadDB.Name)

	return &rec, nil
}

// openTenantConnections opens and validates write + read connections for a tenant.
// When EnableReadReplica is false, the Read handle re-uses the Write pool to avoid
// needing a read replica in development or single-node environments.
func (p *TenantDBPool) openTenantConnections(rec *TenantRecord) (*TenantConnPair, error) {
	log.Println("STEP 3F: Opening DB connections")
	log.Println("WRITE DB:", rec.WriteDB.Host, rec.WriteDB.Port)

	writeDB, err := postgres.ConnectPostgres(rec.WriteDSN)
	if err != nil {
		return nil, fmt.Errorf("write connection: %w", err)
	}
	writeDB.SetMaxOpenConns(p.cfg.MaxOpenConns)
	writeDB.SetMaxIdleConns(p.cfg.MaxIdleConns)
	writeDB.SetConnMaxLifetime(p.cfg.ConnMaxLifetime)

	var readDB *sql.DB
	if p.cfg.EnableReadReplica {
		// [PRODUCTION]: Opens a separate connection to the read replica.
		log.Println("READ DB (replica):", rec.ReadDB.Host, rec.ReadDB.Port)
		readDB, err = postgres.ConnectPostgres(rec.ReadDSN)
		if err != nil {
			writeDB.Close()
			return nil, fmt.Errorf("read connection: %w", err)
		}
		readDB.SetMaxOpenConns(p.cfg.MaxOpenConns)
		readDB.SetMaxIdleConns(p.cfg.MaxIdleConns)
		readDB.SetConnMaxLifetime(p.cfg.ConnMaxLifetime)
	} else {
		// Dev default: Read re-uses the Write pool. No replica needed.
		log.Println("READ DB: using Write pool (EnableReadReplica=false)")
		readDB = writeDB
	}

	log.Println("STEP 3G: DB connections established successfully")
	return &TenantConnPair{
		Write:    writeDB,
		Read:     readDB,
		lastUsed: time.Now(),
	}, nil
}

// startEviction runs in background and evicts tenant pools idle longer than cfg.IdleTTL.
func (p *TenantDBPool) startEviction() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.evictIdle()
		}
	}
}

func (p *TenantDBPool) evictIdle() {
	threshold := time.Now().Add(-p.cfg.IdleTTL)

	p.mu.Lock()
	defer p.mu.Unlock()

	for id, pair := range p.pools {
		if pair.lastUsed.Before(threshold) {
			pair.Write.Close()
			pair.Read.Close()
			delete(p.pools, id)
			log.Printf("[TenantDBPool] evicted idle tenant %q", id)
		}
	}
}
