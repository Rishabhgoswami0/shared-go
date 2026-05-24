package provisioner

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	_ "github.com/lib/pq"
)

// Verifier validates that a newly provisioned tenant database is operational and usable.
type Verifier struct {
	criticalTables []string
}

// NewVerifier constructs a new Verifier with optional critical tables.
func NewVerifier(criticalTables []string) *Verifier {
	return &Verifier{criticalTables: criticalTables}
}

// Verify connects to the database under tenant credentials, runs a ping, checks schemas,
// validates table existence, and runs a transactional write-read capability check.
func (v *Verifier) Verify(ctx context.Context, host string, port int, dbName, user, password string) (int, error) {
	dsn := "postgres://" + user + ":" + password +
		"@" + host + ":" + strconv.Itoa(port) +
		"/" + dbName + "?sslmode=disable"

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return 0, errors.New("verifier: failed to open connection: " + err.Error())
	}
	defer db.Close()

	// 1. Basic Ping Connectivity Test
	if err = db.PingContext(ctx); err != nil {
		return 0, errors.New("verifier: ping failed: " + err.Error())
	}

	// 2. Critical Table Existence Check (if configured)
	for _, tableName := range v.criticalTables {
		var exists bool
		err = db.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables 
				WHERE table_schema = 'public' 
				  AND table_name   = $1
			)
		`, tableName).Scan(&exists)
		if err != nil {
			return 0, errors.New("verifier: critical table check failed for '" + tableName + "': " + err.Error())
		}
		if !exists {
			return 0, errors.New("verifier: schema validation failed — critical table '" + tableName + "' is missing")
		}
	}

	// 3. Functional Write-Read Permission Validation
	// Executes a transactional DDL and DML sequence to ensure the role actually has write access.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, errors.New("verifier: failed to begin verification transaction: " + err.Error())
	}
	defer tx.Rollback() // Safe: rolls back any modifications if we return early on error

	// Create a temp health check table in public schema
	_, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS public.provision_health_check (id INT)`)
	if err != nil {
		return 0, errors.New("verifier: write-read verification failed (cannot CREATE table): " + err.Error())
	}

	// Insert validation record
	_, err = tx.ExecContext(ctx, `INSERT INTO public.provision_health_check (id) VALUES (42)`)
	if err != nil {
		return 0, errors.New("verifier: write-read verification failed (cannot INSERT records): " + err.Error())
	}

	// Read validation record back
	var val int
	err = tx.QueryRowContext(ctx, `SELECT id FROM public.provision_health_check LIMIT 1`).Scan(&val)
	if err != nil {
		return 0, errors.New("verifier: write-read verification failed (cannot SELECT records): " + err.Error())
	}
	if val != 42 {
		return 0, errors.New("verifier: write-read verification failed (data corruption, read back wrong value)")
	}

	// Clean up by dropping the temp table
	_, err = tx.ExecContext(ctx, `DROP TABLE public.provision_health_check`)
	if err != nil {
		return 0, errors.New("verifier: write-read verification failed (cannot DROP table): " + err.Error())
	}

	if err = tx.Commit(); err != nil {
		return 0, errors.New("verifier: write-read verification failed to commit: " + err.Error())
	}

	// 4. Final count of public tables
	var tableCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'").Scan(&tableCount)
	if err != nil {
		return 0, errors.New("verifier: table count query failed: " + err.Error())
	}

	return tableCount, nil
}
