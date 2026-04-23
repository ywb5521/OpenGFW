package report

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/OpenGFW/agent/state"
	"github.com/apernet/OpenGFW/pkg/models"
)

type Collector struct {
	mu        sync.Mutex
	maxEvents int
	events    []models.TrafficEvent
	metrics   map[string]models.MetricSample
	seq       uint64
	store     state.Store
}

func NewCollector(maxEvents int, stores ...state.Store) *Collector {
	var store state.Store
	if len(stores) > 0 {
		store = stores[0]
	}
	c := &Collector{
		maxEvents: maxEvents,
		metrics:   make(map[string]models.MetricSample),
	}
	if store == nil {
		return c
	}
	c.store = store
	if pending, err := store.LoadPendingIngest(context.Background()); err == nil {
		c.events = append(c.events, pending.Events...)
		for _, metric := range pending.Metrics {
			c.metrics[metricKey(metric)] = metric
		}
		c.seq = restoreCollectorSeq(pending.Events)
	}
	return c
}

func (c *Collector) Emit(event models.TrafficEvent) {
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("evt-%d", atomic.AddUint64(&c.seq, 1))
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxEvents > 0 && len(c.events) >= c.maxEvents {
		c.events = append(c.events[:0], c.events[1:]...)
	}
	c.events = append(c.events, event)
	c.persistLocked()
}

func (c *Collector) AddMetric(metric models.MetricSample) {
	if metric.Time.IsZero() {
		metric.Time = time.Now().UTC()
	}
	key := metricKey(metric)
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.metrics[key]; ok {
		existing.Value += metric.Value
		existing.Time = metric.Time
		c.metrics[key] = existing
		c.persistLocked()
		return
	}
	c.metrics[key] = metric
	c.persistLocked()
}

func (c *Collector) DrainEvents(agentID string, limit int) models.EventBatch {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 || limit > len(c.events) {
		limit = len(c.events)
	}
	events := append([]models.TrafficEvent(nil), c.events[:limit]...)
	c.events = append([]models.TrafficEvent(nil), c.events[limit:]...)
	c.persistLocked()
	return models.EventBatch{
		BatchID:   fmt.Sprintf("evt-batch-%d", atomic.AddUint64(&c.seq, 1)),
		AgentID:   agentID,
		CreatedAt: time.Now().UTC(),
		Events:    events,
	}
}

func (c *Collector) RequeueEvents(batch models.EventBatch) {
	if len(batch.Events) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	events := append([]models.TrafficEvent(nil), batch.Events...)
	events = append(events, c.events...)
	if c.maxEvents > 0 && len(events) > c.maxEvents {
		events = events[:c.maxEvents]
	}
	c.events = events
	c.persistLocked()
}

func (c *Collector) DrainMetrics(agentID string, limit int) models.MetricBatch {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, len(c.metrics))
	for key := range c.metrics {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if limit <= 0 || limit > len(keys) {
		limit = len(keys)
	}
	metrics := make([]models.MetricSample, 0, limit)
	for _, key := range keys[:limit] {
		metrics = append(metrics, c.metrics[key])
		delete(c.metrics, key)
	}
	c.persistLocked()
	return models.MetricBatch{
		BatchID:   fmt.Sprintf("metric-batch-%d", atomic.AddUint64(&c.seq, 1)),
		AgentID:   agentID,
		CreatedAt: time.Now().UTC(),
		Metrics:   metrics,
	}
}

func (c *Collector) RequeueMetrics(batch models.MetricBatch) {
	if len(batch.Metrics) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, metric := range batch.Metrics {
		key := metricKey(metric)
		if existing, ok := c.metrics[key]; ok {
			existing.Value += metric.Value
			if metric.Time.After(existing.Time) {
				existing.Time = metric.Time
			}
			c.metrics[key] = existing
			continue
		}
		c.metrics[key] = metric
	}
	c.persistLocked()
}

func (c *Collector) Pending() (events int, metrics int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events), len(c.metrics)
}

func metricKey(metric models.MetricSample) string {
	keys := make([]string, 0, len(metric.Labels))
	for key := range metric.Labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+2)
	parts = append(parts, metric.AgentID, metric.Name)
	for _, key := range keys {
		parts = append(parts, key+"="+metric.Labels[key])
	}
	return strings.Join(parts, "|")
}

func (c *Collector) persistLocked() {
	if c.store == nil {
		return
	}
	metrics := make([]models.MetricSample, 0, len(c.metrics))
	keys := make([]string, 0, len(c.metrics))
	for key := range c.metrics {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		metrics = append(metrics, c.metrics[key])
	}
	_ = c.store.SavePendingIngest(context.Background(), state.PendingIngest{
		Events:  append([]models.TrafficEvent(nil), c.events...),
		Metrics: metrics,
	})
}

func restoreCollectorSeq(events []models.TrafficEvent) uint64 {
	var maxSeq uint64
	for _, event := range events {
		if !strings.HasPrefix(event.EventID, "evt-") {
			continue
		}
		numeric, err := strconv.ParseUint(strings.TrimPrefix(event.EventID, "evt-"), 10, 64)
		if err != nil {
			continue
		}
		if numeric > maxSeq {
			maxSeq = numeric
		}
	}
	return maxSeq
}
