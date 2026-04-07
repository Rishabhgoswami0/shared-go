package postgres

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// MasterDB holds the write and read connections to the master (registry) database.
// The master DB stores tenant routing information (write/read DSNs per tenant).
type MasterDB struct {
	Write *sql.DB
	Read  *sql.DB
}

// NewMasterDB opens and validates both write and read connections to the master database.
func NewMasterDB(writeDSN, readDSN string) (*MasterDB, error) {
	writeDB, err := connectPostgres(writeDSN)
	if err != nil {
		return nil, fmt.Errorf("master-db write: %w", err)
	}

	readDB, err := connectPostgres(readDSN)
	if err != nil {
		writeDB.Close()
		return nil, fmt.Errorf("master-db read: %w", err)
	}

	return &MasterDB{Write: writeDB, Read: readDB}, nil
}

// Close cleanly shuts down both master DB connections.
func (m *MasterDB) Close() {
	if m.Write != nil {
		m.Write.Close()
	}
	if m.Read != nil {
		m.Read.Close()
	}
}

// ConnectPostgres is the public single-connection helper kept for non-tenant services.
func ConnectPostgres(connStr string) (*sql.DB, error) {
	return connectPostgres(connStr)
}

// connectPostgres is the internal helper used by all constructors.
func connectPostgres(connStr string) (*sql.DB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}
