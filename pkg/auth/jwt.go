package auth

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenType represents if the token is for a user or a service
type TokenType string

const (
	TokenTypeUser    TokenType = "user"
	TokenTypeService TokenType = "service"
)

// CustomClaims represents standard and custom claims for the application
type CustomClaims struct {
	TenantID  string    `json:"tenant_id,omitempty"`
	Roles     map[string][]string `json:"roles,omitempty"`
	Type      TokenType `json:"type,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	SessionID string    `json:"session_id,omitempty"` // For backwards compatibility
	jwt.RegisteredClaims
}

// GenerateRS256Token signs a token using the provided RSA private key and inserts 'kid' in headers
func GenerateRS256Token(claims CustomClaims, privateKey *rsa.PrivateKey, kid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// ParseWithLeeway parses a JWT token while applying a clock skew (leeway) of ±30 seconds.
// It returns the parsed token, supporting key identification via 'kid' in the header.
func ParseWithLeeway(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &CustomClaims{}, keyFunc, jwt.WithLeeway(30*time.Second))
}
