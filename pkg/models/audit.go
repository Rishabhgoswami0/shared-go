package models

import (
	"time"

	"github.com/google/uuid"
)

// AuditFields provides a basic, reusable structure for hybrid auditing.
type AuditFields struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	CreatedByID   *uuid.UUID `json:"created_by_id"`
	CreatedByType string    `json:"created_by_type"` // "user" | "system" | "service"
	CreatedByName string    `json:"created_by_name"`
}
