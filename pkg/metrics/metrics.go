package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// GatewayDuplicatePrefixTotal tracks conflicts detected in the routing table.
	GatewayDuplicatePrefixTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_duplicate_prefix_total",
		Help: "Total number of duplicate path prefixes detected during registry updates.",
	}, []string{"prefix", "winning_service", "losing_service"})

	// GatewayRouteRejectionsTotal tracks how many routes were skipped due to conflicts or errors.
	GatewayRouteRejectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_route_rejections_total",
		Help: "Total number of routes rejected or skipped.",
	}, []string{"reason"})

	// Registry Sync Metrics
	RegistrySyncTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_registry_sync_total",
		Help: "Total number of registry synchronization attempts.",
	}, []string{"status"}) // status=success, failure, unchanged

	RegistrySyncFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gateway_registry_sync_failures_total",
		Help: "Total number of failed registry synchronization attempts.",
	})

	RegistrySnapshotVersion = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gateway_registry_snapshot_version",
		Help: "The current version/hash of the registry snapshot being used.",
	}, []string{"version"})

	RegistryApplyDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "gateway_registry_apply_duration_ms",
		Help:    "Duration in milliseconds to apply a new registry snapshot.",
		Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
	})

	RegistrySnapshotSizeBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateway_registry_snapshot_size_bytes",
		Help: "The size in bytes of the last received registry snapshot.",
	})
)
