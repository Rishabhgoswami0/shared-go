package errors

import (
	"encoding/json"
	"net/http"
	"time"

	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

func mapErrorType(code string) string {
	switch code {
	case string(CodeValidationFailed):
		return "validation_error"
	case string(CodeNotFound):
		return "not_found"
	case string(CodeConflict):
		return "conflict"
	case string(CodeTimeout):
		return "timeout"
	case string(CodeForbidden):
		return "forbidden"
	case string(CodeUnauthorized):
		return "unauthorized"
	default:
		return "internal_error"
	}
}

// WriteError is the single, canonical function for writing error responses.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	ctx := r.Context()

	// Classify error to AppError
	appErr := FromError(err)

	// Mandate instance URI (vFinal+ rule)
	appErr.Instance = r.URL.Path

	// Inject context metadata if missing
	if appErr.RequestID == "" {
		appErr.RequestID = sharedctx.GetRequestID(ctx)
		if appErr.RequestID == "" {
			appErr.RequestID = "unknown"
		} // Fallback
	}
	if appErr.TraceID == "" {
		appErr.TraceID = sharedctx.GetTraceID(ctx)
	}

	// ── Structured Logging ────────────────────────────────────────────────
	startTime := sharedctx.GetStartTime(ctx)
	duration := time.Duration(0)
	if !startTime.IsZero() {
		duration = time.Since(startTime)
	}

	// Use context-aware logger (pre-filled with request_id, trace_id, tenant_id)
	ctxLogger := logger.FromContext(ctx)

	baseFields := []zap.Field{
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("error_code", string(appErr.Code)),
		zap.String("error_type", mapErrorType(string(appErr.Code))),
		zap.Int("status", appErr.Status),
		zap.String("detail", appErr.Detail),
		zap.String("client_ip", sharedctx.GetClientIP(ctx)),
		zap.Duration("duration", duration),
		zap.Int64("duration_ms", duration.Milliseconds()),
	}

	if appErr.Status >= 500 {
		errFields := append(baseFields,
			zap.Error(appErr.Raw),
			zap.Stack("stacktrace"), // Capture full stack for internal failures
		)
		ctxLogger.Error("request failed with internal error", errFields...)
	} else {
		// Log 499 (Client Closed Request) specially if mapping was opted in
		if appErr.Code == CodeClientClosed {
			ctxLogger.Warn("client aborted request", baseFields...)
		} else {
			ctxLogger.Warn("request failed with client error", baseFields...)
		}
	}

	// ── HTTP Response (vFinal+ Strict Header Ordering) ───────────────────
	w.Header().Set("Content-Type", "application/problem+json")

	// Default Retry-After for limiters if developer missed it
	if appErr.Status == http.StatusTooManyRequests && appErr.RetryAfter == "" {
		w.Header().Set("Retry-After", "60")
	} else if appErr.RetryAfter != "" {
		w.Header().Set("Retry-After", appErr.RetryAfter)
	}

	w.WriteHeader(appErr.Status)

	if encErr := json.NewEncoder(w).Encode(appErr); encErr != nil {
		ctxLogger.Error("failed to encode error response", zap.Error(encErr))
	}
}
