package auth

import (
	"context"
	"errors"
	"fmt"
)

// AuthContext represents the authenticated identity
type AuthContext struct {
	Subject  string
	TenantID string
	Roles    []string
	JTI      string
	Type     TokenType
	Scope    string
}

type contextKey string

const authContextKey contextKey = "auth_context"

// WithAuthContext stores the AuthContext in the standard context
func WithAuthContext(ctx context.Context, authCtx AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey, authCtx)
}

// FromContext retrieves the AuthContext from the standard context.
func FromContext(ctx context.Context) (AuthContext, bool) {
	authCtx, ok := ctx.Value(authContextKey).(AuthContext)
	return authCtx, ok
}

// EnforceTenant strictly enforces that the user belongs to the requested tenant or is an admin.
// It returns an error if validation fails.
func EnforceTenant(ctx AuthContext, requestedTenant string) error {
	if ctx.Type == TokenTypeService {
		// Service tokens might be global or tenant-specific. 
		// For our architecture, if a service has a specific audience/scope, maybe TenantID rules act differently.
		// For safety, if requestedTenant is strictly provided, we check it.
		if ctx.TenantID != "" && ctx.TenantID != requestedTenant {
			return errors.New("service token tenant mismatch")
		}
		return nil
	}

	if ctx.TenantID != requestedTenant {
		return fmt.Errorf("tenant mismatch: user does not have access to tenant %s", requestedTenant)
	}

	return nil
}

// RequireRole checks if the authenticated context possesses a specific role.
func RequireRole(ctx AuthContext, role string) error {
	for _, r := range ctx.Roles {
		if r == role {
			return nil
		}
	}
	return fmt.Errorf("forbidden: requires role %s", role)
}
