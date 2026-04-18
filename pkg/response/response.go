package response

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
