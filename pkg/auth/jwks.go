package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWKS represents the JSON Web Key Set structure
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

// JWKSClient manages fetching, caching, and rotating JWKS keys
type JWKSClient struct {
	jwksURL     *url.URL
	expectedIss string
	ttl         time.Duration
	client      *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time

	refreshing atomic.Bool
}

// NewJWKSClient initializes a new JWKS client
func NewJWKSClient(jwksURLRaw, expectedIss string, ttl time.Duration) (*JWKSClient, error) {
	u, err := url.Parse(jwksURLRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid JWKS URL: %w", err)
	}

	allowHTTP := os.Getenv("JWKS_ALLOW_HTTP") == "true"
	if !allowHTTP && u.Scheme != "https" {
		return nil, fmt.Errorf("JWKS URL must use HTTPS strictly. Use JWKS_ALLOW_HTTP=true to bypass in dev")
	}

	issURL, err := url.Parse(expectedIss)
	if err != nil {
		return nil, fmt.Errorf("invalid expected issuer: %w", err)
	}

	if u.Host != issURL.Host {
		return nil, fmt.Errorf("JWKS domain %s does not match expected issuer domain %s", u.Host, issURL.Host)
	}

	c := &JWKSClient{
		jwksURL:     u,
		expectedIss: expectedIss,
		ttl:         ttl,
		client: &http.Client{
			Timeout: 2 * time.Second, // 2s timeout constraint
		},
		keys: make(map[string]*rsa.PublicKey),
	}

	// Attempt initial fetch
	c.refresh()

	return c, nil
}

// refresh performs the actual HTTP fetch and updates the keys
func (c *JWKSClient) refresh() error {
	resp, err := c.client.Get(c.jwksURL.String())
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from JWKS: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	parsedKeys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Use == "sig" {
			pubKey, err := c.parseRSA(key)
			if err != nil {
				continue // skip invalid keys
			}
			parsedKeys[key.Kid] = pubKey
		}
	}

	c.mu.Lock()
	c.keys = parsedKeys
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	return nil
}

// parseRSA converts a JWK to an rsa.PublicKey
func (c *JWKSClient) parseRSA(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	eInt := new(big.Int).SetBytes(eBytes).Int64()

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(eInt),
	}, nil
}

// GetKey returns the RSA public key for the given kid. 
// It handles checking TTL and dispatching graceful background refreshes.
func (c *JWKSClient) GetKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, exists := c.keys[kid]
	fetchedAt := c.fetchedAt
	c.mu.RUnlock()

	elapsed := time.Since(fetchedAt)
	
	// If 80% of TTL has passed, trigger an async refresh gracefully (only one routine at a time)
	if elapsed > time.Duration(float64(c.ttl)*0.8) {
		if c.refreshing.CompareAndSwap(false, true) {
			go func() {
				defer c.refreshing.Store(false)
				c.refresh() // Fallback: if it fails, we keep the stale keys as is
			}()
		}
	}

	if !exists {
		// If key not found and we are not recently fetched (e.g. key might be fresh on auth server), trigger force refresh sync
		if elapsed > time.Second {
			c.refresh()
			c.mu.RLock()
			key, exists = c.keys[kid]
			c.mu.RUnlock()
		}

		if !exists {
			return nil, fmt.Errorf("key %s not found in JWKS", kid)
		}
	}

	return key, nil
}

// KeyFunc is used with github.com/golang-jwt/jwt/v5 to provide the verification key
func (c *JWKSClient) KeyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("kid header missing")
	}

	return c.GetKey(kid)
}
