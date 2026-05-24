package provisioner

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"github.com/Rishabhgoswami0/shared-go/pkg/response"
)

var validEnvironments = map[string]bool{
	"DEV":     true,
	"STAGING": true,
	"PROD":    true,
}

// Handler handles HTTP requests for database provisioning.
type Handler struct {
	provisioner *Provisioner
}

// NewHandler constructs a Handler.
func NewHandler(provisioner *Provisioner) *Handler {
	return &Handler{provisioner: provisioner}
}

// Provision handles POST /internal/v1/provision requests from the Control Plane.
func (h *Handler) Provision(w http.ResponseWriter, r *http.Request) {
	// ── Tracing & Correlation: X-Provision-ID ────────────────────────────────
	provisionID := r.Header.Get("X-Provision-ID")
	ctx := r.Context()
	if provisionID != "" {
		ctx = context.WithValue(ctx, "X-Provision-ID", provisionID)
	}

	// Enforce context request timeout
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	l := logger.FromContext(ctx)
	if provisionID != "" {
		l = l.With(zap.String("provision_id", provisionID))
	}

	// Decode payload
	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperrors.WriteError(w, r, apperrors.NewBadRequest(
			apperrors.CodeBadRequest, "invalid JSON body", err,
		))
		return
	}

	// Validate inputs
	if strings.TrimSpace(req.TenantID) == "" {
		apperrors.WriteError(w, r, apperrors.NewBadRequest(
			apperrors.CodeValidationFailed, "tenant_id is required", nil,
		))
		return
	}
	if err := ValidateDBName(req.DBName); err != nil {
		apperrors.WriteError(w, r, apperrors.NewBadRequest(
			apperrors.CodeValidationFailed, err.Error(), nil,
		))
		return
	}
	env := strings.ToUpper(strings.TrimSpace(req.Environment))
	if !validEnvironments[env] {
		apperrors.WriteError(w, r, apperrors.NewBadRequest(
			apperrors.CodeValidationFailed,
			"environment must be one of DEV, STAGING, PROD — got: "+req.Environment,
			nil,
		))
		return
	}
	req.Environment = env // Normalized

	l.Info("provision_request_validated",
		zap.String("tenant_id", req.TenantID),
		zap.String("db_name", req.DBName),
		zap.String("env", req.Environment),
	)

	// Execute database provisioning flow
	resp, err := h.provisioner.Provision(ctx, req)
	if err != nil {
		l.Error("provision_failed",
			zap.String("tenant_id", req.TenantID),
			zap.String("db_name", req.DBName),
			zap.String("env", req.Environment),
			zap.Error(err),
		)
		apperrors.WriteError(w, r, apperrors.NewInternalError(
			apperrors.CodeInternal, "provisioning failed: "+err.Error(), err,
		))
		return
	}

	// Respond on success
	response.WriteJSON(w, http.StatusOK, resp)
}
