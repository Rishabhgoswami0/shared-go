package middleware

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

func safeRequestID(r *http.Request) string {
	id := r.Header.Get("X-Request-ID")
	if len(id) > 0 && len(id) <= 64 {
		return id
	}
	return ""
}

func generateTraceID() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

// PanicRecovery catches any panic in downstream handlers, logs the full stack
// trace, and returns an RFC 7807 Internal Server Error response via WriteError.
// It must be the outermost middleware so it wraps all other handlers.
func PanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// Use context-aware logger to capture any IDs already present
				ctxLogger := logger.FromContext(r.Context())

				reqID := sharedctx.GetRequestID(r.Context())
				if reqID == "" {
					reqID = safeRequestID(r)
					if reqID == "" {
						reqID = uuid.New().String() // Senior feedback: guaranteed fallback
					}
				}

				traceID := sharedctx.GetTraceID(r.Context())
				if traceID == "" {
					traceID = generateTraceID()
				}

				ctxLogger = ctxLogger.With(
					zap.String("request_id", reqID),
					zap.String("trace_id", traceID),
				)

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
