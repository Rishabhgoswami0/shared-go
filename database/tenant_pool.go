package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// ─── Errors ────────────────────────────────────────────────────────────────

var (
	// ErrTenantNotFound is returned when the tenant_id has no record in master-db.
	ErrTenantNotFound = errors.New("tenant not found")

	// ErrTenantInactive is returned when the tenant exists but is not in "active" status.
	ErrTenantInactive = errors.New("tenant is inactive")
)

// ─── TenantRecord ──────────────────────────────────────────────────────────

// TenantRecord mirrors one row from the master-db `tenants` table.
type TenantRecord struct {
	TenantID string
	WriteDSN string
	ReadDSN  string
	Region   string
	Status   string // "active" | "suspended" | "deleted"
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
}

// DefaultPoolConfig returns sensible production defaults.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxOpenConns:    100,
		MaxIdleConns:    20,
		ConnMaxLifetime: 5 * time.Minute,
		IdleTTL:         30 * time.Minute,
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
func (p *TenantDBPool) Get(ctx context.Context, tenantID string) (*TenantConnPair, error) {
	// ── Fast path: already cached ──────────────────────────────────────────
	p.mu.RLock()
	if pair, ok := p.pools[tenantID]; ok {
		pair.lastUsed = time.Now() // safe: time.Time assignment is atomic on 64-bit
		p.mu.RUnlock()
		return pair, nil
	}
	p.mu.RUnlock()

	// ── Slow path: load from master-db ─────────────────────────────────────
	record, err := p.lookupTenant(ctx, tenantID)
	if err != nil {
		return nil, err
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
func (p *TenantDBPool) lookupTenant(ctx context.Context, tenantID string) (*TenantRecord, error) {
	const q = `
		SELECT tenant_id, write_dsn, read_dsn, region, status
		FROM tenants
		WHERE tenant_id = $1
		LIMIT 1
	`
	row := p.masterRead.QueryRowContext(ctx, q, tenantID)

	var rec TenantRecord
	if err := row.Scan(&rec.TenantID, &rec.WriteDSN, &rec.ReadDSN, &rec.Region, &rec.Status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("master-db lookup for tenant %q: %w", tenantID, err)
	}

	if rec.Status != "active" {
		return nil, fmt.Errorf("%w: tenant_id=%s status=%s", ErrTenantInactive, tenantID, rec.Status)
	}

	// ── Decrypt DSNs (AES-256-GCM) ─────────────────────────────────────────
	// DSNs are stored encrypted in master-db. Decrypt them now, in memory only.
	// The plaintext DSN never touches disk or logs.
	writeDSN, err := DecryptDSN(rec.WriteDSN, p.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("tenant %q: write_dsn decryption failed (wrong key or tampered data): %w", tenantID, err)
	}
	readDSN, err := DecryptDSN(rec.ReadDSN, p.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("tenant %q: read_dsn decryption failed (wrong key or tampered data): %w", tenantID, err)
	}

	rec.WriteDSN = writeDSN
	rec.ReadDSN = readDSN

	return &rec, nil
}

// openTenantConnections opens and validates write + read connections for a tenant.
func (p *TenantDBPool) openTenantConnections(rec *TenantRecord) (*TenantConnPair, error) {
	writeDB, err := connectPostgres(rec.WriteDSN)
	if err != nil {
		return nil, fmt.Errorf("write connection: %w", err)
	}
	writeDB.SetMaxOpenConns(p.cfg.MaxOpenConns)
	writeDB.SetMaxIdleConns(p.cfg.MaxIdleConns)
	writeDB.SetConnMaxLifetime(p.cfg.ConnMaxLifetime)

	readDB, err := connectPostgres(rec.ReadDSN)
	if err != nil {
		writeDB.Close()
		return nil, fmt.Errorf("read connection: %w", err)
	}
	readDB.SetMaxOpenConns(p.cfg.MaxOpenConns)
	readDB.SetMaxIdleConns(p.cfg.MaxIdleConns)
	readDB.SetConnMaxLifetime(p.cfg.ConnMaxLifetime)

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
