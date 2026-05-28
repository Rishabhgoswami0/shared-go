package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/Rishabhgoswami0/shared-go/pkg/auth"
	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// IdempotencyStatus represents the processing state of an idempotent request.
type IdempotencyStatus string

const (
	StatusInProgress IdempotencyStatus = "IN_PROGRESS"
	StatusCompleted  IdempotencyStatus = "COMPLETED"
	StatusFailed     IdempotencyStatus = "FAILED"
)

// IdempotencyRecord holds the state of a previously seen idempotency key.
type IdempotencyRecord struct {
	RequestHash string
	Status      IdempotencyStatus
	CreatedAt   time.Time
}

// IdempotencyStore defines how a service stores and retrieves idempotency keys.
type IdempotencyStore interface {
	// CheckAndInsert attempts to insert the new key.
	// If it already exists, it should return the existing record and a custom error (e.g., ErrKeyExists).
	// For simplicity in Phase 1, we assume returning the existing record if found, or nil if newly inserted as IN_PROGRESS.
	GetRecord(ctx context.Context, idempotencyKey, userID, tenantID, endpoint string) (*IdempotencyRecord, error)

	// CreateRecord inserts the initial IN_PROGRESS record. Must be atomic.
	CreateRecord(ctx context.Context, idempotencyKey, userID, tenantID, endpoint, requestHash string) error

	// UpdateStatus transitions the record (e.g. IN_PROGRESS -> COMPLETED).
	UpdateStatus(ctx context.Context, idempotencyKey string, status IdempotencyStatus) error
}

// IdempotencyMiddleware ensures that requests with an "Idempotency-Key" header
// are executed exactly once per user/tenant/endpoint combination.
func IdempotencyMiddleware(store IdempotencyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			idempotencyKey := r.Header.Get("Idempotency-Key")
			if idempotencyKey == "" {
				// Only require Idempotency-Key for non-safe methods (POST, PUT, PATCH)
				if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
					apperrors.WriteError(w, r, apperrors.NewBadRequest(apperrors.CodeValidationFailed, "Idempotency-Key header is required", nil))
					return
				}
				// Skip for GET, DELETE, etc.
				next.ServeHTTP(w, r)
				return
			}

			// 1. Extract Identity from Context (Assuming AuthMiddleware has already run)
			identity, ok := auth.FromContext(r.Context())
			if !ok {
				apperrors.WriteError(w, r, apperrors.NewInternalError(apperrors.CodeInternal, "Failed to retrieve identity from request context", nil))
				return
			}

			userID := identity.Subject
			tenantID := identity.TenantID

			// 2. Compute Request Hash (SHA-256)
			// Read the body, hash it, and restore the body so the handler can read it.
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				apperrors.WriteError(w, r, apperrors.NewInternalError(apperrors.CodeInternal, "Failed to read request body", err))
				return
			}
			// Restore the io.ReadCloser
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			hashBytes := sha256.Sum256(bodyBytes)
			requestHash := hex.EncodeToString(hashBytes[:])
			endpoint := r.Method + " " + r.URL.Path

			// 3. Check Existing Record
			record, err := store.GetRecord(r.Context(), idempotencyKey, userID, tenantID, endpoint)
			if err != nil {
				apperrors.WriteError(w, r, apperrors.NewInternalError(apperrors.CodeInternal, "Failed to check idempotency store", err))
				return
			}

			if record != nil {
				// Record exists
				if record.RequestHash != requestHash {
					apperrors.WriteError(w, r, apperrors.NewBadRequest(apperrors.CodeValidationFailed, "Idempotency key reused with different request payload", nil))
					return
				}

				if record.Status == StatusCompleted {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"message": "Request already processed successfully", "idempotent": true}`))
					return
				}

				// Stale Check (Phase 2): If stuck IN_PROGRESS > 60s, allow retry.
				if record.Status == StatusInProgress && time.Since(record.CreatedAt) > 60*time.Second {
					// Fallthrough and allow CreateRecord (which should overwrite/replace in a robust store, or we can handle it here)
					logger.Log.Warn("idempotency_stale_record",
						zap.String("key", idempotencyKey),
						zap.Time("created_at", record.CreatedAt),
					)
				} else {
					// Status is IN_PROGRESS and NOT stale, or FAILED and we don't support retry yet
					apperrors.WriteError(w, r, apperrors.NewBadRequest(apperrors.CodeValidationFailed, "Request is already being processed", nil))
					return
				}
			}

			// 4. Create IN_PROGRESS record
			err = store.CreateRecord(r.Context(), idempotencyKey, userID, tenantID, endpoint, requestHash)
			if err != nil {
				// Handle unique constraint violation assuming it might be a race condition
				apperrors.WriteError(w, r, apperrors.NewInternalError(apperrors.CodeInternal, "Failed to create idempotency record", err))
				return
			}

			// 5. Wrap response writer to catch status code and update status
			// We use a simplified wrapper to capture if the request succeeded.
			// Next steps: execute business logic
			cw := &captureWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(cw, r)

			// 6. Update status based on success/failure
			// In a real robust system, even 4xx might be 'COMPLETED' processing, 5xx might be 'FAILED'.
			// We'll mark as COMPLETED if it finishes serving.
			// Note: this should be async or in the request context, but for simplicity here:
			newStatus := StatusCompleted
			if cw.statusCode >= 500 {
				newStatus = StatusFailed
			}

			_ = store.UpdateStatus(context.Background(), idempotencyKey, newStatus)
		})
	}
}

// captureWriter captures the status code written by the handler
type captureWriter struct {
	http.ResponseWriter
	statusCode int
}

func (cw *captureWriter) WriteHeader(code int) {
	cw.statusCode = code
	cw.ResponseWriter.WriteHeader(code)
}
