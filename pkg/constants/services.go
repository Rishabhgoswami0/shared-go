package constants

const (
	// Service Constants
	ServiceAuth         = "AUTH"
	ServiceRegistration = "REGISTRATION"
	ServiceTenantMgmt   = "TENANT_MGMT"

	// TenantNamespace is used for deterministic UUID v5 generation.
	// Changing this will break identity lookups for existing tenants.
	TenantNamespace = "e2d83f36-540c-4573-b39f-24fc76214f4e"
)
