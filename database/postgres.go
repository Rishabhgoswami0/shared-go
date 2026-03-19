package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// ConnectPostgres establishes a connection to a PostgreSQL database using the provided connection string.
// It returns a generic *sql.DB pool pointer.
func ConnectPostgres(connStr string) (*sql.DB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Verify the connection is valid
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}
