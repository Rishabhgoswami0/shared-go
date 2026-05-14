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

	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// JWKSOptions allows for fine-tuning the JWKS client behavior.
type JWKSOptions struct {
	AllowHTTP      bool
	Timeout        time.Duration
	Retries        int
	Backoff        time.Duration
	FailOpen       bool   // If true, allows startup even if initial fetch fails
	LocalCachePath string // Path to persist JWKS keys for bootstrap resilience
}

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
	opts        JWKSOptions
	client      *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	rawKeys   []JWK // Store raw keys for persistence
	fetchedAt time.Time

	refreshing atomic.Bool
	isHealthy  atomic.Bool
}

// NewJWKSClient initializes a new JWKS client with default options and env-var fallback.
func NewJWKSClient(jwksURLRaw, expectedIss string, ttl time.Duration) (*JWKSClient, error) {
	opts := JWKSOptions{
		AllowHTTP:      os.Getenv("JWKS_ALLOW_HTTP") == "true",
		Timeout:        2 * time.Second,
		Retries:        3,
		Backoff:        500 * time.Millisecond,
		LocalCachePath: os.Getenv("JWKS_CACHE_PATH"),
	}
	return NewJWKSClientWithOptions(jwksURLRaw, expectedIss, ttl, opts)
}

// NewJWKSClientWithOptions initializes a new JWKS client with explicit options.
func NewJWKSClientWithOptions(jwksURLRaw, expectedIss string, ttl time.Duration, opts JWKSOptions) (*JWKSClient, error) {
	u, err := url.Parse(jwksURLRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid JWKS URL: %w", err)
	}

	if !opts.AllowHTTP && u.Scheme != "https" {
		return nil, fmt.Errorf("JWKS URL must use HTTPS strictly. Use AllowHTTP option for dev")
	}

	issURL, err := url.Parse(expectedIss)
	if err != nil {
		return nil, fmt.Errorf("invalid expected issuer: %w", err)
	}

	if u.Host != issURL.Host {
		return nil, fmt.Errorf("JWKS domain %s does not match expected issuer domain %s", u.Host, issURL.Host)
	}

	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}

	c := &JWKSClient{
		jwksURL:     u,
		expectedIss: expectedIss,
		ttl:         ttl,
		opts:        opts,
		client: &http.Client{
			Timeout: opts.Timeout,
		},
		keys: make(map[string]*rsa.PublicKey),
	}

	// Attempt initial fetch (sync)
	if err := c.refresh(); err != nil {
		logger.Warn("Initial JWKS network fetch failed, attempting cache recovery", zap.Error(err))
		
		// Fallback to local cache if available
		if cacheErr := c.loadFromCache(); cacheErr == nil {
			logger.Info("JWKS recovered from local cache", zap.String("path", opts.LocalCachePath))
		} else if !opts.FailOpen {
			return nil, fmt.Errorf("initial JWKS fetch and cache recovery failed: %w (cache err: %v)", err, cacheErr)
		} else {
			logger.Warn("JWKS startup entering UNAVAILABLE mode (no network, no cache)")
		}
	}

	return c, nil
}

// refresh performs the actual HTTP fetch and updates the keys with retry logic if configured.
func (c *JWKSClient) refresh() error {
	var lastErr error
	maxAttempts := c.opts.Retries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(c.opts.Backoff * time.Duration(attempt))
		}

		resp, err := c.client.Get(c.jwksURL.String())
		if err != nil {
			lastErr = fmt.Errorf("failed to fetch JWKS (attempt %d): %w", attempt+1, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("unexpected status code from JWKS (attempt %d): %d", attempt+1, resp.StatusCode)
			continue
		}

		var jwks JWKS
		if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
			lastErr = fmt.Errorf("failed to decode JWKS (attempt %d): %w", attempt+1, err)
			continue
		}

		parsedKeys := make(map[string]*rsa.PublicKey)
		for _, key := range jwks.Keys {
			// RS256 algorithm enforcement & RSA/sig check
			if key.Kty == "RSA" && key.Use == "sig" && key.Alg == "RS256" {
				pubKey, err := c.parseRSA(key)
				if err != nil {
					continue // skip invalid keys
				}
				parsedKeys[key.Kid] = pubKey
			}
		}

		if len(parsedKeys) == 0 {
			lastErr = fmt.Errorf("no valid RS256 keys found in JWKS (attempt %d)", attempt+1)
			continue
		}

		c.mu.Lock()
		c.keys = parsedKeys
		c.rawKeys = jwks.Keys
		c.fetchedAt = time.Now()
		c.mu.Unlock()

		c.isHealthy.Store(true)

		// 🛡️ Persistence
		if err := c.saveToCache(); err != nil {
			logger.Warn("Failed to save JWKS to local cache", zap.Error(err))
		}

		return nil
	}

	c.isHealthy.Store(false)
	return lastErr
}

func (c *JWKSClient) saveToCache() error {
	if c.opts.LocalCachePath == "" {
		return nil
	}

	c.mu.RLock()
	data := struct {
		Version   string    `json:"version"`
		UpdatedAt time.Time `json:"updated_at"`
		Keys      []JWK     `json:"keys"`
	}{
		Version:   "1.0",
		UpdatedAt: c.fetchedAt,
		Keys:      c.rawKeys,
	}
	c.mu.RUnlock()

	f, err := os.Create(c.opts.LocalCachePath)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(data)
}

func (c *JWKSClient) loadFromCache() error {
	if c.opts.LocalCachePath == "" {
		return fmt.Errorf("local cache path not configured")
	}

	f, err := os.Open(c.opts.LocalCachePath)
	if err != nil {
		return err
	}
	defer f.Close()

	var data struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return err
	}

	parsedKeys := make(map[string]*rsa.PublicKey)
	for _, key := range data.Keys {
		if key.Kty == "RSA" && key.Use == "sig" && key.Alg == "RS256" {
			pubKey, err := c.parseRSA(key)
			if err != nil {
				continue
			}
			parsedKeys[key.Kid] = pubKey
		}
	}

	if len(parsedKeys) == 0 {
		return fmt.Errorf("no valid keys in cache")
	}

	c.mu.Lock()
	c.keys = parsedKeys
	c.rawKeys = data.Keys
	c.fetchedAt = time.Now() // Use current time for TTL check fallback
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
				if err := c.refresh(); err != nil {
					logger.Error("background JWKS refresh failed",
						zap.Error(err),
						zap.String("url", c.jwksURL.String()),
					)
				}
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

// IsHealthy returns true if the last fetch (network or cache) was successful.
func (c *JWKSClient) IsHealthy() bool {
	return c.isHealthy.Load()
}

// HasKeys returns true if the client has any keys loaded (live or cached).
func (c *JWKSClient) HasKeys() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.keys) > 0
}
