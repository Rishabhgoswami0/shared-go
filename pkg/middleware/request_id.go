package middleware

import (
	"net/http"
	"strings"

	"github.com/Rishabhgoswami0/shared-go/pkg/context"
	"github.com/google/uuid"
)

const (
	RequestIDHeader = "X-Request-ID"
	TraceParentHeader = "traceparent"
)

// RequestID adds a unique request ID and W3C trace ID to each request context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Handle Request ID
		requestID := r.Header.Get(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// 2. Handle W3C Trace ID (traceparent)
		traceID := getTraceID(r)

		// Inject into context
		ctx := r.Context()
		ctx = context.WithRequestID(ctx, requestID)
		ctx = context.WithTraceID(ctx, traceID)
		
		// Set in response header for traceability
		w.Header().Set(RequestIDHeader, requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getTraceID extracts the trace ID from the W3C 'traceparent' header.
// Format: version-trace_id-parent_id-flags
// e.g. 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
func getTraceID(r *http.Request) string {
	tp := r.Header.Get(TraceParentHeader)
	if tp != "" {
		parts := strings.Split(tp, "-")
		// We expect at least version, trace-id, and parent-id
		if len(parts) >= 3 && len(parts[1]) == 32 {
			return parts[1]
		}
	}

	// Fallback: generate a new 32-character hex string (16 bytes)
	// For simplicity, we'll use a UUID without hyphens, which is 32 chars.
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}
