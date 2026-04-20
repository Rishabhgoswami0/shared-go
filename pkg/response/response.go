package response

import (
	"encoding/json"
	"net/http"

	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// SuccessResponse is the standard structure for successful API write operations (POST, PUT, DELETE).
type SuccessResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	ID      interface{} `json:"id,omitempty"`
}

// NewSuccess creates a standard success response with a unique identifier.
// Use this for POST and PUT operations.
func NewSuccess(id interface{}, message string) SuccessResponse {
	return SuccessResponse{
		Status:  "success",
		Message: message,
		ID:      id,
	}
}

// NewMessage creates a standard success response without an identifier.
// Use this for DELETE operations.
func NewMessage(message string) SuccessResponse {
	return SuccessResponse{
		Status:  "success",
		Message: message,
	}
}

// WriteJSON is the canonical success responder.
// It ensures headers are set before status and handles encoding failures gracefully.
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Senior feedback: If encoding fails here, we've already sent headers/status.
	// We cannot retract them. We log the error and stop.
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error("failed to encode JSON response", 
			zap.Error(err), 
			zap.Int("status", status))
		// Do not attempt a second write (http.Error) because status is already sent.
	}
}
