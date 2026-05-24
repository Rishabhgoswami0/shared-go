package provisioner

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"

	_ "github.com/lib/pq"
)

// dbNameRegex enforces PostgreSQL-safe database names.
var dbNameRegex = regexp.MustCompile(`^[a-z][a-z0-9\-]{1,62}$`)

// DBCreator handles DDL operations on the database cluster using a superuser/provisioner connection.
type DBCreator struct {
	superDB *sql.DB
	dbHost  string
	dbPort  int
}

// NewDBCreator constructs a DBCreator.
func NewDBCreator(superDB *sql.DB, dbHost string, dbPort int) *DBCreator {
	return &DBCreator{superDB: superDB, dbHost: dbHost, dbPort: dbPort}
}

// ValidateDBName verifies if the database name matches platform constraints.
func ValidateDBName(name string) error {
	if !dbNameRegex.MatchString(name) {
		return errors.New("invalid db_name: must match ^[a-z][a-z0-9\\-]{1,62}$, got: " + name)
	}
	return nil
}

// DBExists checks if a database exists in the cluster.
func (c *DBCreator) DBExists(ctx context.Context, dbName string) (bool, error) {
	var exists bool
	err := c.superDB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)`,
		dbName,
	).Scan(&exists)
	if err != nil {
		return false, errors.New("db_exists check failed: " + err.Error())
	}
	return exists, nil
}

// CreateDatabase creates the tenant isolated database.
func (c *DBCreator) CreateDatabase(ctx context.Context, dbName string) error {
	if err := ValidateDBName(dbName); err != nil {
		return err
	}
	// DDL cannot be parameterized, using quoted identifiers for absolute safety.
	_, err := c.superDB.ExecContext(ctx, `CREATE DATABASE "`+dbName+`"`)
	if err != nil {
		return errors.New("create database failed: " + err.Error())
	}
	return nil
}

// DropDatabase drops the tenant isolated database (typically on abort cleanup).
func (c *DBCreator) DropDatabase(ctx context.Context, dbName string) error {
	_, err := c.superDB.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+dbName+`"`)
	if err != nil {
		return errors.New("drop database failed: " + err.Error())
	}
	return nil
}

// UserExists checks if a PostgreSQL role exists.
func (c *DBCreator) UserExists(ctx context.Context, username string) (bool, error) {
	var exists bool
	err := c.superDB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)`,
		username,
	).Scan(&exists)
	if err != nil {
		return false, errors.New("user_exists check failed: " + err.Error())
	}
	return exists, nil
}

// CreateUsers generates passwords and creates both Read-Write and Read-Only roles for the tenant database.
func (c *DBCreator) CreateUsers(ctx context.Context, tenantID, env, dbName string) (string, string, string, string, error) {
	servicePrefix := "svc"
	parts := strings.Split(dbName, "-")
	if len(parts) > 0 {
		servicePrefix = parts[0]
	}

	shortID := sanitizeTenantIDSegment(tenantID)
	envLower := strings.ToLower(env)
	writeUser := "t_" + servicePrefix + "_" + shortID + "_" + envLower + "_rw"
	readUser := "t_" + servicePrefix + "_" + shortID + "_" + envLower + "_ro"

	writePass, err := generatePassword()
	if err != nil {
		return "", "", "", "", errors.New("write password generation failed: " + err.Error())
	}
	readPass, err := generatePassword()
	if err != nil {
		return "", "", "", "", errors.New("read password generation failed: " + err.Error())
	}

	// Create/Update Read-Write user
	rwExists, err := c.UserExists(ctx, writeUser)
	if err != nil {
		return "", "", "", "", err
	}
	if !rwExists {
		_, err = c.superDB.ExecContext(ctx,
			`CREATE ROLE "`+writeUser+`" WITH LOGIN PASSWORD '`+writePass+`'`)
	} else {
		_, err = c.superDB.ExecContext(ctx,
			`ALTER ROLE "`+writeUser+`" WITH PASSWORD '`+writePass+`'`)
	}
	if err != nil {
		return "", "", "", "", errors.New("create/update write user failed: " + err.Error())
	}

	// Create/Update Read-Only user
	roExists, err := c.UserExists(ctx, readUser)
	if err != nil {
		return "", "", "", "", err
	}
	if !roExists {
		_, err = c.superDB.ExecContext(ctx,
			`CREATE ROLE "`+readUser+`" WITH LOGIN PASSWORD '`+readPass+`'`)
	} else {
		_, err = c.superDB.ExecContext(ctx,
			`ALTER ROLE "`+readUser+`" WITH PASSWORD '`+readPass+`'`)
	}
	if err != nil {
		return "", "", "", "", errors.New("create/update read user failed: " + err.Error())
	}

	// Grant DB permissions
	_, err = c.superDB.ExecContext(ctx,
		`GRANT ALL PRIVILEGES ON DATABASE "`+dbName+`" TO "`+writeUser+`"`)
	if err != nil {
		return "", "", "", "", errors.New("grant write privileges failed: " + err.Error())
	}
	_, err = c.superDB.ExecContext(ctx,
		`GRANT CONNECT ON DATABASE "`+dbName+`" TO "`+readUser+`"`)
	if err != nil {
		return "", "", "", "", errors.New("grant read connect failed: " + err.Error())
	}

	return writeUser, writePass, readUser, readPass, nil
}

// DropUsers drops the generated database roles (on abort cleanup).
func (c *DBCreator) DropUsers(ctx context.Context, tenantID, env, dbName string) {
	servicePrefix := "svc"
	parts := strings.Split(dbName, "-")
	if len(parts) > 0 {
		servicePrefix = parts[0]
	}

	shortID := sanitizeTenantIDSegment(tenantID)
	envLower := strings.ToLower(env)
	writeUser := "t_" + servicePrefix + "_" + shortID + "_" + envLower + "_rw"
	readUser := "t_" + servicePrefix + "_" + shortID + "_" + envLower + "_ro"

	_, _ = c.superDB.ExecContext(ctx, `DROP ROLE IF EXISTS "`+writeUser+`"`)
	_, _ = c.superDB.ExecContext(ctx, `DROP ROLE IF EXISTS "`+readUser+`"`)
}

func sanitizeTenantIDSegment(tenantID string) string {
	clean := strings.ReplaceAll(tenantID, "-", "")
	if len(clean) > 8 {
		return clean[:8]
	}
	return clean
}

func generatePassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
