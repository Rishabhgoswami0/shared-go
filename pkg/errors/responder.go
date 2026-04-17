package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"

	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// WriteError is the single, canonical function for writing error responses.
//
// It:
//   - Converts any error to an AppError (via FromError if needed)
//   - Injects request_id from context into the response
//   - Sets the RFC 7807 Content-Type: application/problem+json
//   - Logs 4xx as Warn, 5xx as Error (with stack trace)
//   - Sets Instance to /errors/{request_id} for traceability
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	requestID := sharedctx.GetRequestID(r.Context())

	// Classify error to AppError
	appErr := FromError(err)

	// Inject observability fields
	appErr.RequestID = requestID
	if requestID != "" {
		appErr.Instance = fmt.Sprintf("/errors/%s", requestID)
	}

	// ── Structured Logging ────────────────────────────────────────────────
	baseFields := []zap.Field{
		zap.String("request_id", requestID),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("code", appErr.Code),
		zap.String("type", appErr.Type),
		zap.Int("status", appErr.Status),
		zap.String("detail", appErr.Detail),
	}

	if appErr.Status >= 500 {
		// 5xx: log as Error with the raw underlying error and a stack trace
		errFields := append(baseFields,
			zap.Error(appErr.Raw),
			zap.String("stack_trace", string(debug.Stack())),
		)
		logger.Error("server error", errFields...)
	} else {
		// 4xx: log as Warn — no need for stack trace, normal business-level event
		logger.Warn("client error", baseFields...)
	}

	// ── HTTP Response ─────────────────────────────────────────────────────
	// RFC 7807 mandates application/problem+json as Content-Type.
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(appErr.Status)

	if encErr := json.NewEncoder(w).Encode(appErr); encErr != nil {
		// Last-resort: if encoding fails we can't do much more.
		logger.Error("failed to encode error response",
			zap.String("request_id", requestID),
			zap.Error(encErr),
		)
	}
}

// WriteJSON writes a successful JSON response with the given status code.
// Centralizing success responses ensures consistent Content-Type handling.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error("failed to encode JSON response", zap.Error(err))
	}
}
