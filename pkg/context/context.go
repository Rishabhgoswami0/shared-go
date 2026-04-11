package context

import (
	"context"
)

type contextKey string

const (
	RequestIDKey contextKey = "request_id"
)

// WithRequestID returns a new context with the provided request ID.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// GetRequestID retrieves the request ID from the context.
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}
