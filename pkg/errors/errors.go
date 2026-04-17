package errors

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

// BaseProblemURL is the base URI for all RFC 7807 problem type identifiers.
// Loaded from environment variable PROBLEM_BASE_URL.
var BaseProblemURL = getBaseProblemURL()

func getBaseProblemURL() string {
	url := os.Getenv("PROBLEM_BASE_URL")
	if url == "" {
		// Sensible default for development
		return "https://api.yourdomain.com/v1/problems/"
	}
	return url
}

// Standard RFC 7807 problem type URIs.
var (
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
	TypeClientClosed       = BaseProblemURL + "client-closed-request"
)

// InvalidParam describes a single field-level validation failure.
type InvalidParam struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// AppError is an RFC 7807 (Problem Details for HTTP APIs) compliant error type.
type AppError struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance,omitempty"`

	// Code is a standardized, machine-readable ErrorCode.
	Code ErrorCode `json:"code,omitempty"`

	// RequestID is injected by WriteError from the request context.
	RequestID string `json:"request_id,omitempty"`

	// TraceID is injected by WriteError for distributed tracing (W3C traceparent).
	TraceID string `json:"trace_id,omitempty"`

	// InvalidParams contains field-level validation errors.
	InvalidParams []InvalidParam `json:"invalid_params,omitempty"`

	// RetryAfter is an optional retry guidance (delta-seconds or HTTP-date).
	// Hidden from JSON; surfaced as Retry-After header.
	RetryAfter string `json:"-"`

	// Raw holds the original underlying error. Hidden from JSON; used for logging only.
	Raw error `json:"-"`
}

// Error implements the error interface, providing a structured log format.
func (e *AppError) Error() string {
	if e.Raw != nil {
		return fmt.Sprintf("status=%d code=%s detail=%s err=%v", e.Status, e.Code, e.Detail, e.Raw)
	}
	return fmt.Sprintf("status=%d code=%s detail=%s", e.Status, e.Code, e.Detail)
}

func (e *AppError) Unwrap() error {
	return e.Raw
}

// ── Fluent Helpers ──────────────────────────────────────────────────────────

func (e *AppError) WithInstance(instance string) *AppError {
	e.Instance = instance
	return e
}

func (e *AppError) WithRetryAfter(retry string) *AppError {
	e.RetryAfter = retry
	return e
}

// ── Factory functions ──────────────────────────────────────────────────────────

// New creates a new AppError.
// NOTE: Use factory functions (NewBadRequest, etc.) whenever possible to ensure consistency.
func New(typ, title string, status int, code ErrorCode, detail string, raw error) *AppError {
	return &AppError{
		Type:   typ,
		Title:  title,
		Status: status,
		Code:   code,
		Detail: detail,
		Raw:    raw,
	}
}

func NewValidationError(detail string, params []InvalidParam) *AppError {
	return New(TypeValidation, "Validation Error", http.StatusUnprocessableEntity, CodeValidationFailed, detail, nil).
		WithInvalidParams(params)
}

func (e *AppError) WithInvalidParams(params []InvalidParam) *AppError {
	e.InvalidParams = params
	return e
}

func NewBadRequest(code ErrorCode, detail string, raw error) *AppError {
	return New(TypeBadRequest, "Bad Request", http.StatusBadRequest, code, detail, raw)
}

func NewUnauthorized(code ErrorCode, detail string, raw error) *AppError {
	return New(TypeUnauthorized, "Unauthorized", http.StatusUnauthorized, code, detail, raw)
}

func NewForbidden(code ErrorCode, detail string, raw error) *AppError {
	return New(TypeForbidden, "Forbidden", http.StatusForbidden, code, detail, raw)
}

func NewNotFound(code ErrorCode, detail string, raw error) *AppError {
	return New(TypeNotFound, "Not Found", http.StatusNotFound, code, detail, raw)
}

func NewConflict(code ErrorCode, detail string, raw error) *AppError {
	return New(TypeConflict, "Conflict", http.StatusConflict, code, detail, raw)
}

func NewTooManyRequests(code ErrorCode, detail string, raw error, retry string) *AppError {
	return New(TypeTooManyRequests, "Too Many Requests", http.StatusTooManyRequests, code, detail, raw).
		WithRetryAfter(retry)
}

func NewInternalError(code ErrorCode, detail string, raw error) *AppError {
	return New(TypeInternal, "Internal Server Error", http.StatusInternalServerError, code, detail, raw)
}

func NewServiceUnavailable(code ErrorCode, detail string, raw error, retry string) *AppError {
	return New(TypeServiceUnavailable, "Service Unavailable", http.StatusServiceUnavailable, code, detail, raw).
		WithRetryAfter(retry)
}

func NewGatewayTimeout(code ErrorCode, detail string, raw error) *AppError {
	return New(TypeGatewayTimeout, "Gateway Timeout", http.StatusGatewayTimeout, code, detail, raw)
}

func NewDBError(detail string, raw error) *AppError {
	return NewServiceUnavailable(CodeServiceUnavailable, detail, raw, "")
}

// ── Error classifier ──────────────────────────────────────────────────────────

func FromError(err error) *AppError {
	if err == nil {
		return nil
	}

	if ae, ok := err.(*AppError); ok {
		return ae
	}

	switch {
	case isErr(err, sql.ErrNoRows):
		return NewNotFound(CodeNotFound, "the requested resource was not found", err)

	case isErr(err, context.DeadlineExceeded):
		return NewGatewayTimeout(CodeTimeout, "the operation timed out", err)

	case isErr(err, context.Canceled):
		// Use dedicated client closed type
		return New(TypeClientClosed, "Client Closed Request", http.StatusBadRequest, CodeClientClosed, "request was canceled", err)

	default:
		return NewInternalError(CodeInternal, "an unexpected error occurred", err)
	}
}

func isErr(err, target error) bool {
	return errIs(err, target)
}
