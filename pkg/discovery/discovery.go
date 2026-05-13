package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sony/gobreaker"
)

// Endpoint represents a resolved service location.
type Endpoint struct {
	ServiceKey  string `json:"service_key"`
	URL         string `json:"internal_url"`
	Environment string `json:"environment"`
	APIVersion  string `json:"api_version"`
}

// Discovery is the interface for service resolution across the ecosystem.
type Discovery interface {
	// Resolve returns all healthy endpoints for a given service key.
	Resolve(ctx context.Context, serviceKey string) ([]Endpoint, error)
}

// CatalogResolver implements Discovery by polling the TMS Registry.
type CatalogResolver struct {
	registryURL string
	client      *http.Client
	cb          *gobreaker.CircuitBreaker
	ttl         time.Duration
	
	cache       map[string]cacheEntry
	mu          sync.RWMutex
}

type cacheEntry struct {
	endpoints []Endpoint
	expiry    time.Time
}

// NewCatalogResolver creates a production-grade resolver with caching and circuit breaking.
func NewCatalogResolver(registryURL string, ttl time.Duration) *CatalogResolver {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}

	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "tms-registry",
		MaxRequests: 5,
		Interval:    10 * time.Second,
		Timeout:     30 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= 10 && failureRatio >= 0.5
		},
	})

	return &CatalogResolver{
		registryURL: registryURL,
		client:      &http.Client{Timeout: 5 * time.Second},
		cb:          cb,
		ttl:         ttl,
		cache:       make(map[string]cacheEntry),
	}
}

func (r *CatalogResolver) Resolve(ctx context.Context, serviceKey string) ([]Endpoint, error) {
	// 1. Check Cache
	r.mu.RLock()
	entry, ok := r.cache[serviceKey]
	r.mu.RUnlock()

	if ok && time.Now().Before(entry.expiry) {
		return entry.endpoints, nil
	}

	// 2. Resolve via Registry with Circuit Breaker
	result, err := r.cb.Execute(func() (interface{}, error) {
		url := fmt.Sprintf("%s/api/v1/services/%s/endpoints", r.registryURL, serviceKey)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}

		// Inject observability headers
		req.Header.Set("X-Internal-Service", "shared-go-resolver")

		resp, err := r.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
		}

		var endpoints []Endpoint
		if err := json.NewDecoder(resp.Body).Decode(&endpoints); err != nil {
			return nil, err
		}

		return endpoints, nil
	})

	if err != nil {
		// If registry is down but we have stale cache, return stale data as fallback
		if ok {
			return entry.endpoints, nil
		}
		return nil, fmt.Errorf("discovery.Resolve: %w", err)
	}

	endpoints := result.([]Endpoint)

	// 3. Update Cache
	r.mu.Lock()
	r.cache[serviceKey] = cacheEntry{
		endpoints: endpoints,
		expiry:    time.Now().Add(r.ttl),
	}
	r.mu.Unlock()

	return endpoints, nil
}
