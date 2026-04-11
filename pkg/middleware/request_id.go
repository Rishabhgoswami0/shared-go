package middleware

import (
	"net/http"

	"github.com/Rishabhgoswami0/shared-go/pkg/context"
	"github.com/google/uuid"
)

const RequestIDHeader = "X-Request-ID"

// RequestID adds a unique request ID to each request context and response header.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Inject into context
		ctx := context.WithRequestID(r.Context(), requestID)
		
		// Set in response header
		w.Header().Set(RequestIDHeader, requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
