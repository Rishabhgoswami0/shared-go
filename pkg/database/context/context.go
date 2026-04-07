package database

import (
	"context"
	"database/sql"
	"errors"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const (
	contextKeyWriteDB contextKey = "tenant_write_db"
	contextKeyReadDB  contextKey = "tenant_read_db"
)

// ErrNoDBInContext is returned when the DB was not injected into the context
// (i.e. the tenant middleware was not applied to the route).
var ErrNoDBInContext = errors.New("database not found in context: is the tenant middleware applied?")

// WithTenantDB returns a new context carrying the tenant's write and read DB pools.
// This is called by the tenant HTTP middleware after a successful pool.Get().
func WithTenantDB(ctx context.Context, pair *TenantConnPair) context.Context {
	ctx = context.WithValue(ctx, contextKeyWriteDB, pair.Write)
	ctx = context.WithValue(ctx, contextKeyReadDB, pair.Read)
	return ctx
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
// Returns ErrNoDBInContext if the middleware was not applied.
func ReadDBFromContext(ctx context.Context) (*sql.DB, error) {
	db, ok := ctx.Value(contextKeyReadDB).(*sql.DB)
	if !ok || db == nil {
		return nil, ErrNoDBInContext
	}
	return db, nil
}
