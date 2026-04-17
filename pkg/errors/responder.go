package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// WriteError is the single, canonical function for writing error responses.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	ctx := r.Context()
	requestID := sharedctx.GetRequestID(ctx)
	traceID := sharedctx.GetTraceID(ctx)
	tenantID := sharedctx.GetTenantID(ctx)
	startTime := sharedctx.GetStartTime(ctx)

	// Classify error to AppError
	appErr := FromError(err)

	// Inject observability fields into the response object
	appErr.RequestID = requestID
	appErr.TraceID = traceID

	if requestID != "" {
		// Professional instance URI: lowercase k-case for the error code
		// e.g. /errors/bad-request/uuid-123
		codePart := strings.ReplaceAll(strings.ToLower(string(appErr.Code)), "_", "-")
		appErr.Instance = fmt.Sprintf("/errors/%s/%s", codePart, requestID)
	}

	// ── Structured Logging ────────────────────────────────────────────────
	duration := time.Duration(0)
	if !startTime.IsZero() {
		duration = time.Since(startTime)
	}

	baseFields := []zap.Field{
		zap.String("request_id", requestID),
		zap.String("trace_id", traceID),
		zap.String("tenant_id", tenantID),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("code", string(appErr.Code)),
		zap.String("type", appErr.Type),
		zap.Int("status", appErr.Status),
		zap.String("detail", appErr.Detail),
		zap.Duration("duration", duration),
	}

	if appErr.Status >= 500 {
		errFields := append(baseFields,
			zap.Error(appErr.Raw),
			zap.String("stack_trace", string(debug.Stack())),
		)
		logger.Error("request failed", errFields...)
	} else {
		// Log 499 (Client Closed Request) specially if mapping was opted in
		if appErr.Code == CodeClientClosed {
			logger.Warn("client aborted request", baseFields...)
		} else {
			logger.Warn("request failed", baseFields...)
		}
	}

	// ── HTTP Response ─────────────────────────────────────────────────────
	w.Header().Set("Content-Type", "application/problem+json")
	
	// Default Retry-After for limiters if developer missed it
	if appErr.Status == http.StatusTooManyRequests && appErr.RetryAfter == "" {
		w.Header().Set("Retry-After", "60")
	} else if appErr.RetryAfter != "" {
		w.Header().Set("Retry-After", appErr.RetryAfter)
	}

	w.WriteHeader(appErr.Status)

	if encErr := json.NewEncoder(w).Encode(appErr); encErr != nil {
		logger.Error("failed to encode error response",
			zap.String("request_id", requestID),
			zap.Error(encErr),
		)
	}
}

// WriteJSON writes a successful JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error("failed to encode JSON response", zap.Error(err))
	}
}
