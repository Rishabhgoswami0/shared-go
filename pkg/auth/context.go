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
	Subject     string
	Name        string
	TenantID    string
	Roles       map[string][]string
	Permissions map[string][]string // Key: Service (uppercase), Value: List of actions stripped of service prefix (e.g. "faculty.read")
	JTI         string
	Type        TokenType
	Scope       string
}

// HasPermission checks if the authenticated context possesses a specific namespaced permission for a service.
// Tenant Admin bypass is explicitly removed to enforce least privilege.
func (ctx AuthContext) HasPermission(service, permissionKey string) bool {
	if ctx.IsSuperAdmin() {
		return true // Platform Super Admin retains inherent system bypass
	}
	if ctx.Permissions == nil {
		return false
	}

	normService := strings.ToUpper(service)
	normPerm := strings.ToLower(permissionKey)

	// Dynamically strip the service prefix from the permission key to check the claims (e.g. "registration.faculty.read" -> "faculty.read")
	prefix := strings.ToLower(service) + "."
	strippedPerm := strings.TrimPrefix(normPerm, prefix)

	perms, ok := ctx.Permissions[normService]
	if !ok {
		return false
	}
	for _, p := range perms {
		if strings.ToLower(p) == strippedPerm {
			return true
		}
	}
	return false
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
// This is the CORE logic for authorization. It implements the hierarchy:
// SUPER_ADMIN (Global) > TENANT_ADMIN (Global) > Service Role
func (ctx AuthContext) HasRole(service, role string) bool {
	if ctx.Roles == nil {
		return false
	}

	normService := strings.ToUpper(service)
	normRole := strings.ToUpper(role)

	// 1. Hierarchy Level 1: SUPER_ADMIN bypasses all checks
	if ctx.IsSuperAdmin() {
		return true
	}

	// 2. Hierarchy Level 2: TENANT_ADMIN bypasses service-level checks WITHIN their tenant
	// (Note: Tenant isolation is already enforced by middleware before this)
	if ctx.IsTenantAdmin() && normService != ServiceGlobal {
		return true
	}

	// 3. Hierarchy Level 3: Specific Service Role check
	roles, ok := ctx.Roles[normService]
	if !ok {
		return false
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

// IsSuperAdmin returns true if the user has the SUPER_ADMIN role globally.
func (ctx AuthContext) IsSuperAdmin() bool {
	globalRoles, ok := ctx.Roles[ServiceGlobal]
	if !ok {
		return false
	}
	for _, r := range globalRoles {
		if strings.ToUpper(r) == RoleSuperAdmin {
			return true
		}
	}
	return false
}

// IsTenantAdmin returns true if the user has the TENANT_ADMIN role globally.
// This also returns true if the user is a SUPER_ADMIN.
func (ctx AuthContext) IsTenantAdmin() bool {
	if ctx.IsSuperAdmin() {
		return true
	}
	globalRoles, ok := ctx.Roles[ServiceGlobal]
	if !ok {
		return false
	}
	for _, r := range globalRoles {
		if strings.ToUpper(r) == "TENANT_ADMIN" {
			return true
		}
	}
	return false
}

// HasAnyServiceRole checks if the authenticated context possesses any of the specific roles for a given service.
func (ctx AuthContext) HasAnyServiceRole(service string, roles []string) bool {
	for _, r := range roles {
		if ctx.HasRole(service, r) {
			return true
		}
	}
	return false
}

