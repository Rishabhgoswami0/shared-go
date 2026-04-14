package context

import (
	"context"
	"database/sql"
	"errors"
	"log"

	"github.com/Rishabhgoswami0/shared-go/pkg/database/tenant"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const (
	contextKeyWriteDB  contextKey = "tenant_write_db"
	contextKeyReadDB   contextKey = "tenant_read_db"
	// contextKeyForceWrite is set per-request (via X-Force-Write header) to
	// override the global ReadAfterWriteConsistency setting.
	contextKeyForceWrite contextKey = "force_write_db"
)

// ErrNoDBInContext is returned when the DB was not injected into the context
// (i.e. the tenant middleware was not applied to the route).
var ErrNoDBInContext = errors.New("database not found in context: is the tenant middleware applied?")

// WithTenantDB returns a new context carrying the tenant's write and read DB pools.
// This is called by the tenant HTTP middleware after a successful pool.Get().
func WithTenantDB(ctx context.Context, pair *tenant.TenantConnPair) context.Context {
	log.Println("STEP 4: DB injected into context")
	ctx = context.WithValue(ctx, contextKeyWriteDB, pair.Write)
	ctx = context.WithValue(ctx, contextKeyReadDB, pair.Read)
	return ctx
}

// WithForceWrite injects a per-request override into the context that forces
// ReadDBFromContext to return the Write DB handle, regardless of the global
// ReadAfterWriteConsistency configuration.
//
// Usage: inject this via middleware when the X-Force-Write: true header is present.
func WithForceWrite(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyForceWrite, true)
}

// IsForceWrite reports whether the current request context has been marked
// to use the Write DB for reads (per-request override).
func IsForceWrite(ctx context.Context) bool {
	v, _ := ctx.Value(contextKeyForceWrite).(bool)
	return v
}

// WriteDBFromContext extracts the tenant write DB from the context.
// Returns ErrNoDBInContext if the middleware was not applied.
func WriteDBFromContext(ctx context.Context) (*sql.DB, error) {
	db, ok := ctx.Value(contextKeyWriteDB).(*sql.DB)
	if !ok || db == nil {
		return nil, ErrNoDBInContext
	}
	return db, nil
}

// ReadDBFromContext extracts the tenant read DB from the context.
// If the request has been marked with WithForceWrite (X-Force-Write header),
// or if global ReadAfterWriteConsistency is enabled (caller passes forceWrite=true),
// the Write DB is returned instead to prevent stale-read bugs.
//
// Usage:
//
//	db, err := context.ReadDBFromContext(ctx)         // normal read
//	db, err := context.ForceWriteReadDB(ctx)          // forced write DB for reads
func ReadDBFromContext(ctx context.Context) (*sql.DB, error) {
	// Per-request override: if ForceWrite is set, return the Write DB.
	if IsForceWrite(ctx) {
		return WriteDBFromContext(ctx)
	}

	db, ok := ctx.Value(contextKeyReadDB).(*sql.DB)
	if !ok || db == nil {
		return nil, ErrNoDBInContext
	}
	return db, nil
}
