package middleware

import (
	"net/http"
	"time"

	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// Logging middleware logs every request with a structured summary.
// It must be placed AFTER RequestID and TenantMiddleware in the chain.
func Logging(l logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Inject start time into context for downstream latency tracking
			ctx := sharedctx.WithStartTime(r.Context(), start)
			r = r.WithContext(ctx)

			// Wrap ResponseWriter to capture status code and response size
			rw := &responseWriter{
				ResponseWriter: w,
				status:         http.StatusOK, // Default to 200
			}

			next.ServeHTTP(rw, r)

			duration := time.Since(start)

			// Safe request size
			requestSize := r.ContentLength
			if requestSize < 0 {
				requestSize = 0
			}

			// Use context-aware logger (pre-filled with request_id, trace_id, tenant_id)
			ctxLogger := logger.FromContext(r.Context())

			// Add middleware order guard
			if r.Context().Value(sharedctx.RequestIDKey) == nil {
				ctxLogger.Warn("missing request_id (middleware order issue)")
			}

			// Standard fields for every request summary
			fields := []zap.Field{
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("route", r.Pattern), // Normalized route pattern (Go 1.22+)
				zap.Int("status", rw.status),
				zap.Int64("duration_ms", duration.Milliseconds()),
				zap.Int64("request_size", requestSize),
				zap.Int("response_size", rw.size),
			}

			// Condition-based logs
			threshold := logger.GlobalConfig.SlowRequestThreshold
			if threshold == 0 {
				threshold = 1000 * time.Millisecond
			}

			if duration > threshold {
				ctxLogger.Warn("slow request detected", fields...)
			}

			// Level logic: 2xx = INFO, 4xx = WARN, 5xx = ERROR
			if rw.status >= 500 {
				ctxLogger.Error("request failed", fields...)
			} else if rw.status >= 400 {
				ctxLogger.Warn("request completed with client error", fields...)
			} else {
				ctxLogger.Info("request completed", fields...)
			}
		})
	}
}

// responseWriter captures the HTTP status code and body size.
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}
