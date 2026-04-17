package errors

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
)

// BaseProblemURL is the base URI for all RFC 7807 problem type identifiers.
// Update this to your real documentation domain before going to production.
const BaseProblemURL = "https://api.yourdomain.com/problems/"

// Standard RFC 7807 problem type URIs.
const (
	TypeValidation         = BaseProblemURL + "validation-error"
	TypeBadRequest         = BaseProblemURL + "bad-request"
	TypeUnauthorized       = BaseProblemURL + "unauthorized"
	TypeForbidden          = BaseProblemURL + "forbidden"
	TypeNotFound           = BaseProblemURL + "not-found"
	TypeConflict           = BaseProblemURL + "conflict"
	TypeTooManyRequests    = BaseProblemURL + "too-many-requests"
	TypeInternal           = BaseProblemURL + "internal-error"
	TypeServiceUnavailable = BaseProblemURL + "service-unavailable"
	TypeGatewayTimeout     = BaseProblemURL + "gateway-timeout"
)

// InvalidParam describes a single field-level validation failure.
// Included in AppError.InvalidParams for validation errors.
type InvalidParam struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// AppError is an RFC 7807 (Problem Details for HTTP APIs) compliant error type.
// It is the single, canonical error type used across all services.
//
// JSON representation follows RFC 7807:
//
//	Content-Type: application/problem+json
type AppError struct {
	// Type is a URI that identifies the problem type. Clients can use
	// this to look up documentation. (RFC 7807 §3.1)
	Type string `json:"type"`

	// Title is a short, human-readable summary of the problem type.
	// It MUST NOT change between occurrences of the same problem. (RFC 7807 §3.1)
	Title string `json:"title"`

	// Status mirrors the HTTP status code. (RFC 7807 §3.1)
	Status int `json:"status"`

	// Detail is a human-readable explanation specific to this occurrence.
	// Safe to expose to end users. (RFC 7807 §3.1)
	Detail string `json:"detail"`

	// Instance is a URI reference that identifies this specific occurrence.
	// Typically set to /errors/{request_id} by WriteError. (RFC 7807 §3.1)
	Instance string `json:"instance,omitempty"`

	// Code is an optional, machine-readable error code for client-side logic.
	// e.g. "EMAIL_ALREADY_EXISTS", "VALIDATION_FAILED"
	Code string `json:"code,omitempty"`

	// RequestID is injected by WriteError from the request context.
	RequestID string `json:"request_id,omitempty"`

	// InvalidParams contains field-level validation errors for TypeValidation errors.
	InvalidParams []InvalidParam `json:"invalid_params,omitempty"`

	// Raw holds the original underlying error. Hidden from JSON; used for logging only.
	Raw error `json:"-"`
}

// Error implements the error interface, producing a log-friendly string.
func (e *AppError) Error() string {
	if e.Raw != nil {
		return fmt.Sprintf("[%d %s] %s: %v", e.Status, e.Code, e.Detail, e.Raw)
	}
	return fmt.Sprintf("[%d %s] %s", e.Status, e.Code, e.Detail)
}

// Unwrap allows errors.Is/errors.As to inspect the underlying raw error.
func (e *AppError) Unwrap() error {
	return e.Raw
}

// ── Factory functions ──────────────────────────────────────────────────────────

// NewValidationError creates a 422 Unprocessable Entity error with field-level detail.
// Use this when request body or query params fail validation.
func NewValidationError(code, detail string, params []InvalidParam) *AppError {
	return &AppError{
		Type:          TypeValidation,
		Title:         "Validation Error",
		Status:        http.StatusUnprocessableEntity,
		Detail:        detail,
		Code:          code,
		InvalidParams: params,
	}
}

// NewBadRequest creates a 400 Bad Request error.
// Use this for malformed JSON, invalid path params, etc.
func NewBadRequest(code, detail string, raw error) *AppError {
	return &AppError{
		Type:   TypeBadRequest,
		Title:  "Bad Request",
		Status: http.StatusBadRequest,
		Detail: detail,
		Code:   code,
		Raw:    raw,
	}
}

// NewUnauthorized creates a 401 Unauthorized error.
func NewUnauthorized(code, detail string, raw error) *AppError {
	return &AppError{
		Type:   TypeUnauthorized,
		Title:  "Unauthorized",
		Status: http.StatusUnauthorized,
		Detail: detail,
		Code:   code,
		Raw:    raw,
	}
}

// NewForbidden creates a 403 Forbidden error.
func NewForbidden(code, detail string, raw error) *AppError {
	return &AppError{
		Type:   TypeForbidden,
		Title:  "Forbidden",
		Status: http.StatusForbidden,
		Detail: detail,
		Code:   code,
		Raw:    raw,
	}
}

// NewNotFound creates a 404 Not Found error.
func NewNotFound(code, detail string, raw error) *AppError {
	return &AppError{
		Type:   TypeNotFound,
		Title:  "Not Found",
		Status: http.StatusNotFound,
		Detail: detail,
		Code:   code,
		Raw:    raw,
	}
}

// NewConflict creates a 409 Conflict error.
func NewConflict(code, detail string, raw error) *AppError {
	return &AppError{
		Type:   TypeConflict,
		Title:  "Conflict",
		Status: http.StatusConflict,
		Detail: detail,
		Code:   code,
		Raw:    raw,
	}
}

// NewTooManyRequests creates a 429 Too Many Requests error.
func NewTooManyRequests(code, detail string, raw error) *AppError {
	return &AppError{
		Type:   TypeTooManyRequests,
		Title:  "Too Many Requests",
		Status: http.StatusTooManyRequests,
		Detail: detail,
		Code:   code,
		Raw:    raw,
	}
}

// NewInternal creates a 500 Internal Server Error.
// Expose only a safe Detail to clients; log the Raw error internally.
func NewInternal(code, detail string, raw error) *AppError {
	return &AppError{
		Type:   TypeInternal,
		Title:  "Internal Server Error",
		Status: http.StatusInternalServerError,
		Detail: detail,
		Code:   code,
		Raw:    raw,
	}
}

// NewServiceUnavailable creates a 503 Service Unavailable error.
func NewServiceUnavailable(code, detail string, raw error) *AppError {
	return &AppError{
		Type:   TypeServiceUnavailable,
		Title:  "Service Unavailable",
		Status: http.StatusServiceUnavailable,
		Detail: detail,
		Code:   code,
		Raw:    raw,
	}
}

// NewGatewayTimeout creates a 504 Gateway Timeout error.
func NewGatewayTimeout(code, detail string, raw error) *AppError {
	return &AppError{
		Type:   TypeGatewayTimeout,
		Title:  "Gateway Timeout",
		Status: http.StatusGatewayTimeout,
		Detail: detail,
		Code:   code,
		Raw:    raw,
	}
}

// ── Convenience aliases ────────────────────────────────────────────────────────

// NewDBError is a convenience alias for database-related service unavailability.
func NewDBError(detail string, raw error) *AppError {
	return NewServiceUnavailable("DATABASE_ERROR", detail, raw)
}

// ── Error classifier ──────────────────────────────────────────────────────────

// FromError classifies a plain Go error into an AppError.
// This is a FALLBACK only — business logic should always return explicit AppErrors.
//
// Mapping table:
//
//	sql.ErrNoRows              → 404 Not Found
//	context.DeadlineExceeded   → 504 Gateway Timeout
//	context.Canceled           → 500 Internal (client closed, treated server-side)
//	*AppError (already typed)  → returned as-is
//	everything else            → 500 Internal Server Error
func FromError(err error) *AppError {
	if err == nil {
		return nil
	}

	// Already an AppError — pass through without wrapping.
	if ae, ok := err.(*AppError); ok {
		return ae
	}

	switch {
	case isErr(err, sql.ErrNoRows):
		return NewNotFound("RESOURCE_NOT_FOUND", "the requested resource was not found", err)

	case isErr(err, context.DeadlineExceeded):
		return NewGatewayTimeout("TIMEOUT", "the operation timed out", err)

	case isErr(err, context.Canceled):
		// Client disconnected; treat as internal from the server's perspective.
		return NewInternal("REQUEST_CANCELED", "request was canceled", err)

	default:
		return NewInternal("INTERNAL_SERVER_ERROR", "an unexpected error occurred", err)
	}
}

// isErr wraps errors.Is to keep switch cases readable.
func isErr(err, target error) bool {
	// Use stdlib errors.Is via import-aliasing to avoid package-name conflict.
	return errIs(err, target)
}
