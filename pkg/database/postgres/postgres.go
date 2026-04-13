package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// MasterDB holds the write and read connections to the master (registry) database.
type MasterDB struct {
	Write *sql.DB
	Read  *sql.DB
}

// NewMasterDB opens and validates both write and read connections with retries.
func NewMasterDB(writeDSN, readDSN string) (*MasterDB, error) {
	writeDB, err := connectWithRetry(writeDSN, 3, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("master-db write: %w", err)
	}

	readDB, err := connectWithRetry(readDSN, 3, 2*time.Second)
	if err != nil {
		writeDB.Close()
		return nil, fmt.Errorf("master-db read: %w", err)
	}

	return &MasterDB{Write: writeDB, Read: readDB}, nil
}

// Ping checks if both write and read databases are reachable.
func (m *MasterDB) Ping(ctx context.Context) error {
	if m.Write != nil {
		if err := m.Write.PingContext(ctx); err != nil {
			return fmt.Errorf("write db ping: %w", err)
		}
	} else {
		return fmt.Errorf("write db is nil")
	}

	if m.Read != nil {
		if err := m.Read.PingContext(ctx); err != nil {
			return fmt.Errorf("read db ping: %w", err)
		}
	} else {
		return fmt.Errorf("read db is nil")
	}

	return nil
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

// ConnectPostgres is the public single-connection helper with retries.
func ConnectPostgres(connStr string) (*sql.DB, error) {
	return connectWithRetry(connStr, 3, 2*time.Second)
}

func connectWithRetry(connStr string, retries int, interval time.Duration) (*sql.DB, error) {
	var db *sql.DB
	var err error

	for i := 0; i < retries; i++ {
		db, err = sql.Open("postgres", connStr)
		if err == nil {
			err = db.Ping()
			if err == nil {
				return db, nil
			}
		}

		if db != nil {
			db.Close()
		}

		if i < retries-1 {
			time.Sleep(interval)
		}
	}

	return nil, fmt.Errorf("after %d attempts, failed to connect: %w", retries, err)
}
