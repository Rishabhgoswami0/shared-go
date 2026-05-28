// Package audit provides a structured, async, non-blocking audit event pipeline.
//
// Design principles:
//   - Non-blocking: Emit() never blocks the request goroutine. Overflows are
//     counted and logged rather than causing backpressure.
//   - Structured: All audit events are emitted as zap fields, not raw strings.
//     This integrates with the existing shared-go logger and observability stack.
//   - Immutable: Events are value types; no mutation after Emit().
//   - Drain-safe: Shutdown() flushes the buffered channel before returning.
//   - Extraction-ready: The Pipeline interface allows future implementations
//     (DB write, Kafka publish, SIEM push) without changing callers.
package audit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// Event represents an immutable audit record emitted by any middleware or handler.
// Fields map directly to municipal compliance requirements:
// tenant isolation, actor identity, capability, action outcome, and traceability.
type Event struct {
	// Tracing
	RequestID string `json:"request_id"`
	TraceID   string `json:"trace_id"`

	// Identity
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`

	// Action
	Service  string `json:"service"`
	Module   string `json:"module,omitempty"`
	Action   string `json:"action"`
	Endpoint string `json:"endpoint"`

	// Authorization
	Capability     []string `json:"capability,omitempty"`
	Mode           string   `json:"mode,omitempty"`
	LifecycleState string   `json:"lifecycle_state,omitempty"`

	// Outcome
	Level   string `json:"level"`  // "INFO" | "WARN" | "ERROR"
	Outcome string `json:"outcome"` // "ALLOWED" | "DENIED" | "ERROR"
	Reason  string `json:"reason,omitempty"`

	// Metadata
	Environment string    `json:"environment,omitempty"`
	Version     int       `json:"entitlement_version,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// Pipeline is the abstraction for emitting audit events.
// Future implementations: AsyncAuditPipeline (current), DBPipeline, KafkaPipeline.
type Pipeline interface {
	// Emit enqueues an audit event for async processing. Non-blocking.
	// If the internal buffer is full, the event is dropped and a metric is incremented.
	Emit(event Event)

	// Shutdown drains the pipeline and stops all workers. Blocks until drained or ctx canceled.
	Shutdown(ctx context.Context)
}

// AsyncPipeline is the production Pipeline implementation.
// Events are queued in a buffered channel and processed by a fixed worker pool.
type AsyncPipeline struct {
	ch          chan Event
	wg          sync.WaitGroup
	dropped     atomic.Int64
	log         logger.Logger
	once        sync.Once
}

// NewAsyncPipeline creates and starts the audit worker pool.
//
//   - bufferSize: capacity of the internal event queue (recommended: 10_000)
//   - workers:    number of goroutines draining the queue (recommended: 10)
//   - log:        the shared-go logger used by audit workers
func NewAsyncPipeline(bufferSize, workers int, log logger.Logger) *AsyncPipeline {
	if bufferSize <= 0 {
		bufferSize = 10_000
	}
	if workers <= 0 {
		workers = 10
	}

	p := &AsyncPipeline{
		ch:  make(chan Event, bufferSize),
		log: log,
	}

	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	return p
}

// Emit enqueues an audit event without blocking the caller.
// Drops the event (with a logged warning) if the buffer is full.
func (p *AsyncPipeline) Emit(event Event) {
	select {
	case p.ch <- event:
	default:
		// Buffer full — increment drop counter and warn once per burst.
		dropped := p.dropped.Add(1)
		if dropped == 1 || dropped%1000 == 0 {
			p.log.Warn("audit_pipeline_buffer_full",
				zap.Int64("dropped_total", dropped),
			)
		}
	}
}

// Shutdown closes the event channel and waits for all workers to drain.
// Call this during graceful shutdown after all request handlers have stopped.
func (p *AsyncPipeline) Shutdown(ctx context.Context) {
	p.once.Do(func() {
		close(p.ch)
	})

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.log.Info("audit_pipeline_shutdown_complete")
	case <-ctx.Done():
		p.log.Warn("audit_pipeline_shutdown_timeout", zap.Error(ctx.Err()))
	}
}

// worker drains the event channel and logs each event using structured zap fields.
func (p *AsyncPipeline) worker() {
	defer p.wg.Done()
	for event := range p.ch {
		p.log.Info("audit_event",
			zap.String("request_id", event.RequestID),
			zap.String("trace_id", event.TraceID),
			zap.String("tenant_id", event.TenantID),
			zap.String("user_id", event.UserID),
			zap.String("service", event.Service),
			zap.String("module", event.Module),
			zap.String("action", event.Action),
			zap.String("endpoint", event.Endpoint),
			zap.Strings("capability", event.Capability),
			zap.String("mode", event.Mode),
			zap.String("lifecycle_state", event.LifecycleState),
			zap.String("level", event.Level),
			zap.String("outcome", event.Outcome),
			zap.String("reason", event.Reason),
			zap.String("environment", event.Environment),
			zap.Int("entitlement_version", event.Version),
			zap.Time("timestamp", event.Timestamp),
		)
	}
}

// NoopPipeline is a Pipeline that silently discards all events.
// Use in tests or when auditing is explicitly disabled.
type NoopPipeline struct{}

func (n *NoopPipeline) Emit(_ Event)              {}
func (n *NoopPipeline) Shutdown(_ context.Context) {}
