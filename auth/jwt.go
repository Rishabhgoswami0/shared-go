package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// CustomClaims represents the standard JWT claims along with our custom session_id claim.
type CustomClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	jwt.RegisteredClaims
}

// GenerateToken generates a JWT that includes a newly generated UUID as the session_id.
// It returns the encoded token string, the generated session_id, and any error encountered.
func GenerateToken(userID string, secretKey []byte) (string, string, error) {
	sessionID := uuid.New().String()

	claims := CustomClaims{
		SessionID: sessionID,
		UserID:    userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "shared-go-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, sessionID, nil
}

// ValidateToken parses the token string, validates the signature, and extracts/returns the session_id and user_id.
func ValidateToken(tokenString string, secretKey []byte) (string, string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return "", "", fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims.SessionID, claims.UserID, nil
	}

	return "", "", fmt.Errorf("invalid token")
}
