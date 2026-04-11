package errors

import (
	"fmt"
	"net/http"
)

// AppError represents a standardized application error.
type AppError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id,omitempty"`
	Raw        error  `json:"-"` // Hidden from JSON, for logging
}

func (e *AppError) Error() string {
	if e.Raw != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Raw)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Raw
}

// NewAppError creates a new AppError.
func NewAppError(status int, code, message string, raw error) *AppError {
	return &AppError{
		StatusCode: status,
		Code:       code,
		Message:    message,
		Raw:        raw,
	}
}

// Helper factory functions for common error types
func NewBadRequest(code, message string, raw error) *AppError {
	return NewAppError(http.StatusBadRequest, code, message, raw)
}

func NewNotFound(code, message string, raw error) *AppError {
	return NewAppError(http.StatusNotFound, code, message, raw)
}

func NewConflict(code, message string, raw error) *AppError {
	return NewAppError(http.StatusConflict, code, message, raw)
}

func NewInternal(code, message string, raw error) *AppError {
	return NewAppError(http.StatusInternalServerError, code, message, raw)
}

func NewForbidden(code, message string, raw error) *AppError {
	return NewAppError(http.StatusForbidden, code, message, raw)
}
