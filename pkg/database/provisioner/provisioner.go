// Package provisioner orchestrates database provisioning for tenant isolated microservice databases.
package provisioner

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
)

// ProvisionRequest is the standard payload sent by the Control Plane.
type ProvisionRequest struct {
	TenantID    string `json:"tenant_id"`
	DBName      string `json:"db_name"`
	Environment string `json:"environment"`
}

// DBConnInfo holds connection details returned to the Control Plane.
type DBConnInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// ProvisionResponse is returned to the Control Plane on success.
type ProvisionResponse struct {
	Status           string     `json:"status"`
	DBReady          bool       `json:"db_ready"`
	MigrationApplied bool       `json:"migration_applied"`
	SeedApplied      bool       `json:"seed_applied"`
	SchemaVersion    string     `json:"schema_version"`
	WriteDB          DBConnInfo `json:"write_db"`
	ReadDB           DBConnInfo `json:"read_db"`
}

// Provisioner orchestrates the full database provisioning lifecycle.
type Provisioner struct {
	creator      *DBCreator
	migrator     *Migrator
	seeder       *Seeder
	verifier     *Verifier
	superDSNBase string
}

// NewProvisioner constructs a new Provisioner with all required execution engines.
func NewProvisioner(creator *DBCreator, migrator *Migrator, seeder *Seeder, verifier *Verifier, superDSNBase string) *Provisioner {
	return &Provisioner{
		creator:      creator,
		migrator:     migrator,
		seeder:       seeder,
		verifier:     verifier,
		superDSNBase: superDSNBase,
	}
}

// Provision runs the complete provisioning sequence safely and idempotently.
func (p *Provisioner) Provision(ctx context.Context, req ProvisionRequest) (*ProvisionResponse, error) {
	// Extract ProvisionID from context if available for correlation
	provisionID := ""
	if pID := ctx.Value("X-Provision-ID"); pID != nil {
		if s, ok := pID.(string); ok {
			provisionID = s
		}
	}

	l := logger.FromContext(ctx).With(
		zap.String("tenant_id", req.TenantID),
		zap.String("db_name", req.DBName),
		zap.String("env", req.Environment),
	)
	if provisionID != "" {
		l = l.With(zap.String("provision_id", provisionID))
	}

	l.Info("provision_started")

	// ── Pre-flight: validate migration + seed files BEFORE any DB ops ─────────
	migEntries, err := p.migrator.loadEntries()
	if err != nil {
		return nil, errors.New("provision: failed to load migration entries: " + err.Error())
	}
	schemaEntries := p.migrator.filterNonSeed(migEntries)
	if len(schemaEntries) == 0 {
		return nil, errors.New("provision: no schema migration files found — aborting to prevent empty DB")
	}
	l.Info("migration_validated", zap.Int("file_count", len(schemaEntries)))

	// Validate seed files for DEV only
	if strings.ToUpper(req.Environment) == "DEV" {
		seedEntries := p.seeder.filterSeed(migEntries)
		if len(seedEntries) == 0 {
			return nil, errors.New("provision: no seed files found for DEV — aborting")
		}
		l.Info("seed_validated", zap.Int("file_count", len(seedEntries)), zap.String("env", req.Environment))
	}

	// ── Idempotency: skip CREATE DATABASE if it already exists ────────────────
	dbCtx, dbCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbCancel()

	alreadyExists, err := p.creator.DBExists(dbCtx, req.DBName)
	if err != nil {
		return nil, errors.New("provision: db existence check failed: " + err.Error())
	}
	l.Info("db_existence_checked",
		zap.String("db_name", req.DBName),
		zap.Bool("already_exists", alreadyExists),
	)

	dbCreated := false
	if !alreadyExists {
		if err := p.creator.CreateDatabase(dbCtx, req.DBName); err != nil {
			return nil, err
		}
		dbCreated = true
		l.Info("db_created", zap.String("db_name", req.DBName))
	}

	// ── Deferred orphan cleanup: drop DB + users if any later step fails ──────
	var provErr error
	defer func() {
		if provErr != nil && dbCreated {
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanCancel()

			if dropErr := p.creator.DropDatabase(cleanCtx, req.DBName); dropErr != nil {
				l.Error("orphan_db_cleanup_failed",
					zap.String("db_name", req.DBName),
					zap.Error(dropErr),
				)
			} else {
				l.Warn("orphan_db_cleanup_success", zap.String("db_name", req.DBName))
			}
			p.creator.DropUsers(cleanCtx, req.TenantID, req.Environment, req.DBName)
		}
	}()

	// ── Create DB users ───────────────────────────────────────────────────────
	userCtx, userCancel := context.WithTimeout(ctx, 5*time.Second)
	defer userCancel()

	writeUser, writePass, readUser, readPass, err := p.creator.CreateUsers(
		userCtx, req.TenantID, req.Environment, req.DBName,
	)
	if err != nil {
		provErr = err
		return nil, err
	}
	l.Info("user_created",
		zap.String("write_user", writeUser),
		zap.String("read_user", readUser),
	)

	// ── Open a connection to the new tenant DB for migrations ─────────────────
	tenantDSN := p.superDSNBase + "/" + req.DBName + "?sslmode=disable"
	tenantDB, err := sql.Open("postgres", tenantDSN)
	if err != nil {
		provErr = errors.New("provision: failed to open tenant DB connection: " + err.Error())
		return nil, provErr
	}
	defer tenantDB.Close()

	// ── Run schema migrations ─────────────────────────────────────────────────
	migCtx, migCancel := context.WithTimeout(ctx, 30*time.Second)
	defer migCancel()

	l.Info("migration_started", zap.String("db_name", req.DBName))
	schemaVersion, err := p.migrator.Run(migCtx, tenantDB)
	if err != nil {
		provErr = err
		return nil, err
	}
	l.Info("migration_completed",
		zap.String("db_name", req.DBName),
		zap.String("schema_version", schemaVersion),
	)

	// ── Run seed data (DEV only) ──────────────────────────────────────────────
	seedCtx, seedCancel := context.WithTimeout(ctx, 10*time.Second)
	defer seedCancel()

	seedApplied, err := p.seeder.Run(seedCtx, tenantDB, req.Environment)
	if err != nil {
		provErr = err
		return nil, err
	}
	if seedApplied {
		l.Info("seed_applied",
			zap.String("db_name", req.DBName),
			zap.String("env", req.Environment),
		)
	}

	// ── Grant Permissions on objects in public schema ─────────────────────────
	grantCtx, grantCancel := context.WithTimeout(ctx, 5*time.Second)
	defer grantCancel()

	// ── Grant Schema-Level Access (PostgreSQL 15+ requires explicit USAGE + CREATE) ─
	// In PG15+, CREATE on the public schema is no longer granted to PUBLIC by default.
	// Without USAGE + CREATE, the write user cannot run DDL (e.g. CREATE TABLE) inside
	// the public schema — which would break the verifier and future migration runs.
	_, err = tenantDB.ExecContext(grantCtx, `GRANT USAGE, CREATE ON SCHEMA public TO "`+writeUser+`"`)
	if err != nil {
		provErr = errors.New("provision: failed to grant schema access to write user: " + err.Error())
		return nil, provErr
	}
	_, err = tenantDB.ExecContext(grantCtx, `GRANT USAGE ON SCHEMA public TO "`+readUser+`"`)
	if err != nil {
		provErr = errors.New("provision: failed to grant schema access to read user: " + err.Error())
		return nil, provErr
	}

	// Grant to Write User
	_, err = tenantDB.ExecContext(grantCtx, `GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "`+writeUser+`"`)
	if err != nil {
		provErr = errors.New("provision: failed to grant table privileges to write user: " + err.Error())
		return nil, provErr
	}
	_, err = tenantDB.ExecContext(grantCtx, `GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "`+writeUser+`"`)
	if err != nil {
		provErr = errors.New("provision: failed to grant sequence privileges to write user: " + err.Error())
		return nil, provErr
	}

	// Grant to Read User
	_, err = tenantDB.ExecContext(grantCtx, `GRANT SELECT ON ALL TABLES IN SCHEMA public TO "`+readUser+`"`)
	if err != nil {
		provErr = errors.New("provision: failed to grant table privileges to read user: " + err.Error())
		return nil, provErr
	}
	_, err = tenantDB.ExecContext(grantCtx, `GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "`+readUser+`"`)
	if err != nil {
		provErr = errors.New("provision: failed to grant sequence privileges to read user: " + err.Error())
		return nil, provErr
	}

	// ── Future-Proofing: ALTER DEFAULT PRIVILEGES ─────────────────────────────
	_, err = tenantDB.ExecContext(grantCtx, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "`+writeUser+`"`)
	if err != nil {
		provErr = errors.New("provision: failed to set default privileges for write user: " + err.Error())
		return nil, provErr
	}
	_, err = tenantDB.ExecContext(grantCtx, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "`+readUser+`"`)
	if err != nil {
		provErr = errors.New("provision: failed to set default privileges for read user: " + err.Error())
		return nil, provErr
	}

	l.Info("permissions_granted", zap.String("db_name", req.DBName))

	// ── Verify DB ─────────────────────────────────────────────────────────────
	verCtx, verCancel := context.WithTimeout(ctx, 10*time.Second)
	defer verCancel()

	tableCount, err := p.verifier.Verify(
		verCtx,
		p.creator.dbHost,
		p.creator.dbPort,
		req.DBName,
		writeUser,
		writePass,
	)
	if err != nil {
		provErr = err
		return nil, err
	}
	l.Info("verification_passed",
		zap.String("db_name", req.DBName),
		zap.Int("table_count", tableCount),
	)

	// ── Build response ────────────────────────────────────────────────────────
	resp := &ProvisionResponse{
		Status:           "PROVISIONED",
		DBReady:          true,
		MigrationApplied: true,
		SeedApplied:      seedApplied,
		SchemaVersion:    schemaVersion,
		WriteDB: DBConnInfo{
			Host:     p.creator.dbHost,
			Port:     p.creator.dbPort,
			Name:     req.DBName,
			User:     writeUser,
			Password: writePass,
		},
		ReadDB: DBConnInfo{
			Host:     p.creator.dbHost,
			Port:     p.creator.dbPort,
			Name:     req.DBName,
			User:     readUser,
			Password: readPass,
		},
	}

	l.Info("provision_completed",
		zap.String("tenant_id", req.TenantID),
		zap.String("db_name", req.DBName),
		zap.String("env", req.Environment),
		zap.String("schema_version", schemaVersion),
		zap.Bool("seed_applied", seedApplied),
		zap.String("write_user", writeUser),
		zap.String("write_host", p.creator.dbHost+":"+strconv.Itoa(p.creator.dbPort)),
	)

	return resp, nil
}

// Helper types/functions for internal operations
type migrationEntry struct {
	version     string
	description string
	filename    string
}

// fsLoader reads files from fs.FS and returns sorted entries.
func loadFSEntries(fSys fs.FS, dir string) ([]migrationEntry, error) {
	files, err := fs.ReadDir(fSys, dir)
	if err != nil {
		return nil, errors.New("failed to read migration dir: " + err.Error())
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
			filename:    dir + "/" + f.Name(),
		})
	}
	return entries, nil
}
