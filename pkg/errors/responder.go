package errors

import (
	"encoding/json"
	"net/http"

	"github.com/Rishabhgoswami0/shared-go/pkg/context"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

type errorResponse struct {
	Status    string `json:"status"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// WriteError centralizes error responding and logging.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	requestID := context.GetRequestID(r.Context())

	var appErr *AppError
	if ae, ok := err.(*AppError); ok {
		appErr = ae
	} else {
		// Fallback for unexpected errors
		appErr = NewInternal("INTERNAL_SERVER_ERROR", "An unexpected error occurred", err)
	}

	appErr.RequestID = requestID

	// Log based on status code
	if appErr.StatusCode >= 500 {
		logger.Error("Server error",
			zap.String("request_id", requestID),
			zap.String("code", appErr.Code),
			zap.String("message", appErr.Message),
			zap.Error(appErr.Raw),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
		)
	} else {
		logger.Info("Client error",
			zap.String("request_id", requestID),
			zap.String("code", appErr.Code),
			zap.String("message", appErr.Message),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(appErr.StatusCode)
	
	resp := errorResponse{
		Status:    "error",
		Code:      appErr.Code,
		Message:   appErr.Message,
		RequestID: requestID,
	}
	
	json.NewEncoder(w).Encode(resp)
}
