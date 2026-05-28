package errors

// ErrorCode is a type-safe string for machine-readable error codes.
type ErrorCode string

const (
	// ── Standard HTTP-mapped codes ────────────────────────────────────────────
	CodeValidationFailed        ErrorCode = "VALIDATION_FAILED"
	CodeBadRequest              ErrorCode = "BAD_REQUEST"
	CodeNotFound                ErrorCode = "RESOURCE_NOT_FOUND"
	CodeConflict                ErrorCode = "CONFLICT"
	CodeInternal                ErrorCode = "INTERNAL_SERVER_ERROR"
	CodeTimeout                 ErrorCode = "TIMEOUT"
	CodeUnauthorized            ErrorCode = "UNAUTHORIZED"
	CodeForbidden               ErrorCode = "FORBIDDEN"
	CodeTooManyRequests         ErrorCode = "TOO_MANY_REQUESTS"
	CodeServiceUnavailable      ErrorCode = "SERVICE_UNAVAILABLE"
	CodeClientClosed            ErrorCode = "CLIENT_CLOSED_REQUEST"

	// ── Auth / Identity codes ─────────────────────────────────────────────────
	CodeUserExists               ErrorCode = "AUTH_USER_EXISTS"
	CodeInvalidInternalSignature ErrorCode = "INVALID_INTERNAL_SIGNATURE"

	// ── Replay / Idempotency codes ────────────────────────────────────────────
	// CodeReplayDetected is returned when a request nonce has already been seen.
	// Used by identity and entitlement middleware to prevent replay attacks.
	CodeReplayDetected ErrorCode = "REPLAY_DETECTED"

	// CodeIdempotencyConflict is returned when an Idempotency-Key is reused
	// with a different request payload, indicating a client programming error.
	CodeIdempotencyConflict ErrorCode = "IDEMPOTENCY_CONFLICT"

	// ── Concurrency / Consistency codes ──────────────────────────────────────
	// CodeOptimisticLockConflict is returned when an update detects a version
	// mismatch, signalling a concurrent modification by another actor.
	CodeOptimisticLockConflict ErrorCode = "OPTIMISTIC_LOCK_CONFLICT"

	// ── Tenant entitlement / lifecycle codes ─────────────────────────────────
	// CodeFeatureNotEntitled is returned when a tenant attempts to access a
	// capability that is not included in their subscription package.
	CodeFeatureNotEntitled ErrorCode = "FEATURE_NOT_ENTITLED"

	// CodeTenantSuspended is returned when the tenant account is suspended
	// (e.g. non-payment) and all mutating operations are blocked.
	CodeTenantSuspended ErrorCode = "TENANT_SUSPENDED"

	// CodeTenantExpired is returned when the tenant subscription has expired
	// and the system is in read-only or access-denied mode.
	CodeTenantExpired ErrorCode = "TENANT_EXPIRED"

	// ── Domain / Business rule codes ─────────────────────────────────────────
	// CodeOperationNotPermitted is returned when a business rule prevents the
	// requested operation (e.g. mutation during migration window, read-only year).
	CodeOperationNotPermitted ErrorCode = "OPERATION_NOT_PERMITTED"
)
