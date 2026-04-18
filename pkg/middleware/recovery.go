package middleware

import (
	"net/http"

	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// PanicRecovery catches any panic in downstream handlers, logs the full stack
// trace, and returns an RFC 7807 Internal Server Error response via WriteError.
// It must be the outermost middleware so it wraps all other handlers.
func PanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// Use context-aware logger to capture any IDs already present
				ctxLogger := logger.FromContext(r.Context())

				ctxLogger.Error("panic recovered",
					zap.Any("panic", rec),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
					zap.Stack("stacktrace"), // Senior level: structured stack trace
				)

				// Use WriteError so the panic response is also RFC 7807 compliant
				// and carries the request_id.
				apperrors.WriteError(w, r,
					apperrors.NewInternalError(apperrors.CodeInternal, "an unexpected error occurred", nil),
				)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
