package errors

// ErrorCode is a type-safe string for machine-readable error codes.
type ErrorCode string

const (
	CodeValidationFailed   ErrorCode = "VALIDATION_FAILED"
	CodeBadRequest         ErrorCode = "BAD_REQUEST"
	CodeNotFound           ErrorCode = "RESOURCE_NOT_FOUND"
	CodeConflict           ErrorCode = "CONFLICT"
	CodeInternal           ErrorCode = "INTERNAL_SERVER_ERROR"
	CodeTimeout            ErrorCode = "TIMEOUT"
	CodeUnauthorized       ErrorCode = "UNAUTHORIZED"
	CodeForbidden          ErrorCode = "FORBIDDEN"
	CodeTooManyRequests    ErrorCode = "TOO_MANY_REQUESTS"
	CodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	CodeClientClosed       ErrorCode = "CLIENT_CLOSED_REQUEST"
)
