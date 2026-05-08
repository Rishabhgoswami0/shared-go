package auth

import (
	"net/http"

	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
)

// RequireSuperAdmin strictly enforces the global SUPER_ADMIN role.
func RequireSuperAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := FromContext(r.Context())
		if !ok || !ctx.IsSuperAdmin() {
			apperrors.WriteError(w, r, apperrors.NewForbidden(apperrors.CodeForbidden, "forbidden: requires super admin role", nil))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireTenantAdmin enforces the global TENANT_ADMIN role (or SUPER_ADMIN).
func RequireTenantAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := FromContext(r.Context())
		if !ok || !ctx.IsTenantAdmin() {
			apperrors.WriteError(w, r, apperrors.NewForbidden(apperrors.CodeForbidden, "forbidden: requires tenant admin role", nil))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireServiceRole enforces a specific role for a given service.
// Hierarchy: SUPER_ADMIN and TENANT_ADMIN bypass this check.
func RequireServiceRole(service, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, ok := FromContext(r.Context())
			if !ok || !ctx.HasRole(service, role) {
				apperrors.WriteError(w, r, apperrors.NewForbidden(apperrors.CodeForbidden, "forbidden: requires role "+role+" for service "+service, nil))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyServiceRole enforces that the user has at least one of the specified roles for a service.
// Hierarchy: SUPER_ADMIN and TENANT_ADMIN bypass this check.
func RequireAnyServiceRole(service string, roles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, ok := FromContext(r.Context())
			if !ok || !ctx.HasAnyServiceRole(service, roles) {
				apperrors.WriteError(w, r, apperrors.NewForbidden(apperrors.CodeForbidden, "forbidden: insufficient permissions for service "+service, nil))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
