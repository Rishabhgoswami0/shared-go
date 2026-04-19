# Shared Go Library (`shared-go`)

The core engine of the microservice ecosystem. This library provides standardized utilities for multi-tenant database pooling, idempotency, audit compliance, and error handling.

## 🏗️ Core Modules

### 1. Database Management (`pkg/database`)
-   **`TenantDBPool`**: A high-performance connection manager that resolves tenant-specific DSNs from the Master Registry.
    -   **In-Memory Caching**: DSNs are cached with a configurable TTL (default 5m) to prevent Master DB contention.
    -   **Service-Specific Resolution**: Supports cross-service isolation where different services (AUTH, REGISTRATION) can have unique DB clusters for the same tenant.
-   **`Encryption`**: AES-256-GCM utilities for encrypting sensitive DSNs at rest in the Master DB.

### 2. Middleware (`pkg/middleware`)
-   **`IdempotencyMiddleware`**: Protects mutating endpoints (POST/PUT/DELETE) from double-submission.
    -   **Stale Request Recovery**: Automatically unlocks `IN_PROGRESS` requests after 60 seconds if the original worker died.
-   **`TenantMiddleware`**: Injects tenant metadata from the JWT into the request context.
-   **`CorrelationMiddleware`**: Generates and propagates `X-Request-ID` for cross-service logging.

### 3. Models & Audit (`pkg/models`)
-   **`AuditFields`**: Standardized struct for tracking record lifecycle (`created_by_id`, `created_at`, etc.).
-   **System vs User Support**: Supports nullable `CreatedByID` to distinguish between human-initiated and system-triggered actions.

### 4. Identity & Auth (`pkg/auth`)
-   **`JWKSClient`**: High-performance public key fetcher and validator with background rotation support.
-   **`AuthMiddleware`**: Enforces RS256 JWT validation and requirement checks.

---

## ⚙️ Shared Constants

The library defines standardized identifiers for the whole platform:
-   **Service Codes**: `AUTH`, `REGISTRATION`, `TENANT_MGMT`.
-   **Tenant Namespace**: Fixed UUID used for deterministic **UUID v5** generation.

---

## 🛠️ Usage for Developers

When creating a new service:
1.  Initialize the **Master DB** connection in `main.go`.
2.  Initialize the `TenantDBPool` using the Master DB.
3.  Inject the `Pool` into your repositories or middleware.
4.  Use `WriterFromContext(ctx)` in your database operations to support transaction propagation.
