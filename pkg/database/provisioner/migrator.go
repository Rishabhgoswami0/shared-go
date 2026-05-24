package provisioner

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"sort"
	"strings"

	_ "github.com/lib/pq"
)

// Migrator runs versioned schema migrations against a tenant isolated database.
type Migrator struct {
	migrationFS fs.FS
	dir         string
}

// NewMigrator constructs a new Migrator pointing to the embedded migrations filesystem.
func NewMigrator(migrationFS fs.FS, dir string) *Migrator {
	return &Migrator{
		migrationFS: migrationFS,
		dir:         dir,
	}
}

// Run applies all non-seed migrations to the database.
func (m *Migrator) Run(ctx context.Context, db *sql.DB) (string, error) {
	entries, err := m.loadEntries()
	if err != nil {
		return "", err
	}

	nonSeedEntries := m.filterNonSeed(entries)
	if len(nonSeedEntries) == 0 {
		return "", errors.New("migrator: no schema migration files found — aborting provision")
	}

	// Bootstrap schema_migrations table
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     VARCHAR(50) PRIMARY KEY,
			description TEXT        NOT NULL DEFAULT '',
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return "", errors.New("migrator: failed to ensure schema_migrations table: " + err.Error())
	}

	var latestVersion string
	for _, entry := range nonSeedEntries {
		// Idempotency: check if already applied
		var applied bool
		err = db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`,
			entry.version,
		).Scan(&applied)
		if err != nil {
			return "", errors.New("migrator: version check failed for " + entry.version + ": " + err.Error())
		}
		if applied {
			latestVersion = entry.version
			continue
		}

		// Read and execute
		sqlBytes, err := fs.ReadFile(m.migrationFS, entry.filename)
		if err != nil {
			return "", errors.New("migrator: failed to read file " + entry.filename + ": " + err.Error())
		}

		if _, err = db.ExecContext(ctx, string(sqlBytes)); err != nil {
			return "", errors.New("migrator: failed to apply " + entry.version + " (" + entry.filename + "): " + err.Error())
		}

		// Record version
		_, err = db.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, description) VALUES ($1, $2)`,
			entry.version, entry.description,
		)
		if err != nil {
			return "", errors.New("migrator: failed to record version " + entry.version + ": " + err.Error())
		}

		latestVersion = entry.version
	}

	return latestVersion, nil
}

func (m *Migrator) loadEntries() ([]migrationEntry, error) {
	files, err := fs.ReadDir(m.migrationFS, m.dir)
	if err != nil {
		return nil, errors.New("migrator: failed to read embedded migration dir: " + err.Error())
	}

	var entries []migrationEntry
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".sql") {
			continue
		}
		name := strings.TrimSuffix(f.Name(), ".sql")
		parts := strings.SplitN(name, "_", 2)
		version := parts[0]
		description := ""
		if len(parts) == 2 {
			description = parts[1]
		}
		entries = append(entries, migrationEntry{
			version:     version,
			description: description,
			filename:    m.dir + "/" + f.Name(),
		})
	}

	// Sort ascending by version string
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].version < entries[j].version
	})

	return entries, nil
}

func (m *Migrator) filterNonSeed(entries []migrationEntry) []migrationEntry {
	var out []migrationEntry
	for _, e := range entries {
		if !strings.Contains(strings.ToLower(e.description), "seed") {
			out = append(out, e)
		}
	}
	return out
}
