package context

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// contextKeyTx is the context key for an active *sql.Tx.
const contextKeyTx contextKey = "tenant_tx"

// ErrNoTxInContext is returned when a transaction is expected but was not started.
var ErrNoTxInContext = fmt.Errorf("no active transaction in context: call RunInTx first")

// WithTx returns a new context carrying the active transaction.
// This is called internally by RunInTx — services and repositories
// should never call this directly.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, contextKeyTx, tx)
}

// TxFromContext extracts the active *sql.Tx from the context.
// Returns (nil, nil) if no transaction is active — callers should
// fall back to the regular *sql.DB in that case.
func TxFromContext(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(contextKeyTx).(*sql.Tx)
	return tx, ok && tx != nil
}

// WriteExecer is the common interface satisfied by both *sql.DB and *sql.Tx.
// Repositories can accept this instead of a concrete type to work with
// both transactional and non-transactional callers transparently.
type WriteExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// WriterFromContext returns the active *sql.Tx if a transaction is in progress,
// otherwise falls back to the tenant Write *sql.DB.
// Repositories call this instead of WriteDBFromContext so they automatically
// participate in any surrounding transaction with zero extra plumbing.
func WriterFromContext(ctx context.Context) (WriteExecer, error) {
	// If a transaction is active, always prefer it.
	if tx, ok := TxFromContext(ctx); ok {
		return tx, nil
	}
	// Fall back to the plain write DB.
	return WriteDBFromContext(ctx)
}

// RunInTx executes fn inside a database transaction against the tenant Write DB.
//
// Lifecycle:
//   - Calls BeginTx on the tenant write DB.
//   - Injects the *sql.Tx into the context via WithTx.
//   - If fn returns nil → Commit.
//   - If fn returns an error → Rollback (best-effort).
//
// Usage in a Service method:
//
//	err := dbctx.RunInTx(ctx, func(txCtx context.Context) error {
//	    if _, err := s.repo.Create(txCtx, faculty); err != nil {
//	        return err // triggers rollback
//	    }
//	    return s.repo.LogActivity(txCtx, faculty.ID) // in same tx
//	})
func RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	db, err := WriteDBFromContext(ctx)
	if err != nil {
		return fmt.Errorf("RunInTx: %w", err)
	}

	logger.Log.Info("db_tx_starting")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("RunInTx: begin transaction: %w", err)
	}

	// Inject the transaction into the context for downstream callers.
	txCtx := WithTx(ctx, tx)

	// Run the caller's work inside the transaction.
	if err := fn(txCtx); err != nil {
		logger.Log.Error("db_tx_rollback", zap.Error(err))
		// Best-effort rollback — log if it also fails but return original error.
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("RunInTx: fn error: %w; rollback error: %v", err, rbErr)
		}
		return err
	}

	// All operations succeeded — commit.
	if err := tx.Commit(); err != nil {
		logger.Log.Error("db_tx_commit_failed", zap.Error(err))
		return fmt.Errorf("RunInTx: commit: %w", err)
	}

	logger.Log.Info("db_tx_committed")
	return nil
}
