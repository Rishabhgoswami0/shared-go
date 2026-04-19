# Shared Go Library

A centralized repository of common Go packages, utilities, and middleware used across the multi-tenant microservice fleet. Hosted at `github.com/Rishabhgoswami0/shared-go`.

## 📦 Available Packages

### 🔒 `pkg/auth`
Production-grade authentication utilities based on **RS256** and **JWKS**.
- `CustomClaims`: Standardized JWT claims including `tenant_id` and `roles`.
- `AuthMiddleware`: High-performance middleware for JWKS validation and identity injection.
- `JWKSClient`: Caching client for automated public key fetching.

### 🗄️ `pkg/db`
Database abstraction layer for multi-tenant sharding.
- `DatabaseConfig`: Standardized configuration for Master and Tenant DBs.
- `TenantPool`: Management of concurrent connections to multiple organization shards.
- `Encryption`: AES-256-GCM utilities for securing DSNs at rest.

### 🚨 `pkg/errors`
Standardized error handling implementing **RFC 7807** (Problem Details for HTTP APIs).
- `WriteError`: Responder for consistent JSON error structures.
- `AppError`: Domain-specific error types with Request-ID correlation.

### 📝 `pkg/logging`
Structured logging wrappers around `zap`.
- Consistent log levels and tenant/request metadata injection.

---

## 🛠️ Usage in Microservices

Add the library to your `go.mod`:
```bash
go get github.com/Rishabhgoswami0/shared-go@latest
```

Ensure `GOPRIVATE` is configured if the repository is private:
```bash
export GOPRIVATE=github.com/Rishabhgoswami0/*
```

---

## 🚀 Contribution & Versioning
This library follows Semantic Versioning. Major architectural changes must be tagged and pushed to GitHub for services to pull via `go mod`.
```bash
git tag vX.X.X
git push origin vX.X.X
```
