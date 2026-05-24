package provisioner

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"strings"
)

// Seeder applies environment-specific seed data to a newly provisioned tenant DB.
type Seeder struct {
	migrationFS fs.FS
	dir         string
}

// NewSeeder constructs a new Seeder.
func NewSeeder(migrationFS fs.FS, dir string) *Seeder {
	return &Seeder{
		migrationFS: migrationFS,
		dir:         dir,
	}
}

// Run executes seed files in DEV environment only, tracked via schema_migrations.
func (s *Seeder) Run(ctx context.Context, db *sql.DB, env string) (bool, error) {
	if strings.ToUpper(env) != "DEV" {
		return false, nil
	}

	migrator := &Migrator{migrationFS: s.migrationFS, dir: s.dir}
	entries, err := migrator.loadEntries()
	if err != nil {
		return false, errors.New("seeder: failed to load migration entries: " + err.Error())
	}

	seedEntries := s.filterSeed(entries)
	if len(seedEntries) == 0 {
		return false, errors.New("seeder: no seed files found for DEV environment — aborting provision")
	}

	for _, entry := range seedEntries {
		var applied bool
		err = db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`,
			entry.version,
		).Scan(&applied)
		if err != nil {
			return false, errors.New("seeder: version check failed for " + entry.version + ": " + err.Error())
		}
		if applied {
			continue
		}

		sqlBytes, err := fs.ReadFile(s.migrationFS, entry.filename)
		if err != nil {
			return false, errors.New("seeder: failed to read seed file " + entry.filename + ": " + err.Error())
		}

		if _, err = db.ExecContext(ctx, string(sqlBytes)); err != nil {
			return false, errors.New("seeder: failed to apply seed " + entry.version + ": " + err.Error())
		}

		// Record seed version applied to avoid re-running on retry
		_, err = db.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, description) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			entry.version, entry.description,
		)
		if err != nil {
			return false, errors.New("seeder: failed to record seed version " + entry.version + ": " + err.Error())
		}
	}

	return true, nil
}

func (s *Seeder) filterSeed(entries []migrationEntry) []migrationEntry {
	var out []migrationEntry
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.description), "seed") {
			out = append(out, e)
		}
	}
	return out
}
