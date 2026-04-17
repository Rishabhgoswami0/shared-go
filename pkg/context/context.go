package context

import (
	"context"
	"time"
)

type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	StartTimeKey contextKey = "start_time"
	TraceIDKey   contextKey = "trace_id"
	TenantIDKey  contextKey = "tenant_id"
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

// WithStartTime adds a start time to the context for latency tracking.
func WithStartTime(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, StartTimeKey, t)
}

// GetStartTime retrieves the start time from the context.
func GetStartTime(ctx context.Context) time.Time {
	if t, ok := ctx.Value(StartTimeKey).(time.Time); ok {
		return t
	}
	return time.Time{}
}

// WithTraceID adds a trace ID to the context.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey, traceID)
}

// GetTraceID retrieves the trace ID from the context.
func GetTraceID(ctx context.Context) string {
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok {
		return traceID
	}
	return ""
}

// WithTenantID adds a tenant ID to the context.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantIDKey, tenantID)
}

// GetTenantID retrieves the tenant ID from the context.
func GetTenantID(ctx context.Context) string {
	if tenantID, ok := ctx.Value(TenantIDKey).(string); ok {
		return tenantID
	}
	return ""
}
