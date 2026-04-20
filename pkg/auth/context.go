package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	RoleAdmin      = "ADMIN"
	RoleSuperAdmin = "SUPER_ADMIN"

	ServiceRegistration = "REGISTRATION"
	ServiceAuth         = "AUTH"
	ServiceGlobal       = "GLOBAL"
)


// AuthContext represents the authenticated identity
type AuthContext struct {
	Subject  string
	TenantID string
	Roles    map[string][]string
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

// HasRole checks if the authenticated context possesses a specific role for a given service.
// Both service and role are case-insensitive as they are normalized using strings.ToUpper.
func (ctx AuthContext) HasRole(service, role string) bool {
	if ctx.Roles == nil {
		return false
	}

	normService := strings.ToUpper(service)
	normRole := strings.ToUpper(role)

	roles, ok := ctx.Roles[normService]
	if !ok {
		// Fallback to "GLOBAL" if the specific service doesn't have it
		roles, ok = ctx.Roles[ServiceGlobal]
		if !ok {
			return false
		}
	}

	for _, r := range roles {
		if strings.ToUpper(r) == normRole {
			return true
		}
	}
	return false
}

// RequireRole checks if the authenticated context possesses a specific role for a given service.
// This is a wrapper around HasRole that returns an error for middleware usage.
func RequireRole(ctx AuthContext, service, role string) error {
	if ctx.HasRole(service, role) {
		return nil
	}
	return fmt.Errorf("forbidden: requires role %s for service %s", role, service)
}
