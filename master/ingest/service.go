package ingest

import (
	"fmt"
	"strings"
	"sync"
	"time"

	masterstate "github.com/apernet/OpenGFW/master/state"
	"github.com/apernet/OpenGFW/pkg/models"
)

type Snapshot struct {
	Events  []models.TrafficEvent
	Metrics []models.MetricSample
}

type Service struct {
	mu            sync.RWMutex
	maxEvents     int
	maxMetrics    int
	events        []models.TrafficEvent
	metrics       []models.MetricSample
	persist       func(masterstate.IngestSnapshot) error
	appendEvents  func([]models.TrafficEvent) error
	appendMetrics func([]models.MetricSample) error
}

func NewService(maxEvents, maxMetrics int) *Service {
	return NewServiceWithSnapshot(maxEvents, maxMetrics, masterstate.IngestSnapshot{}, nil)
}

func NewServiceWithSnapshot(maxEvents, maxMetrics int, snapshot masterstate.IngestSnapshot, persist func(masterstate.IngestSnapshot) error) *Service {
	return NewServiceWithSnapshotAndAppenders(maxEvents, maxMetrics, snapshot, persist, nil, nil)
}

func NewServiceWithSnapshotAndAppenders(maxEvents, maxMetrics int, snapshot masterstate.IngestSnapshot, persist func(masterstate.IngestSnapshot) error, appendEvents func([]models.TrafficEvent) error, appendMetrics func([]models.MetricSample) error) *Service {
	if maxEvents <= 0 {
		maxEvents = 10000
	}
	if maxMetrics <= 0 {
		maxMetrics = 10000
	}
	return &Service{
		maxEvents:     maxEvents,
		maxMetrics:    maxMetrics,
		events:        append([]models.TrafficEvent(nil), snapshot.Events...),
		metrics:       append([]models.MetricSample(nil), snapshot.Metrics...),
		persist:       persist,
		appendEvents:  appendEvents,
		appendMetrics: appendMetrics,
	}
}

func PrepareEventBatch(batch models.EventBatch) (models.EventBatch, error) {
	agentID := strings.TrimSpace(batch.AgentID)
	if agentID == "" {
		return models.EventBatch{}, fmt.Errorf("agentId is required")
	}
	if batch.CreatedAt.IsZero() {
		batch.CreatedAt = time.Now().UTC()
	}
	events := make([]models.TrafficEvent, 0, len(batch.Events))
	for index, event := range batch.Events {
		if strings.TrimSpace(event.Type) == "" {
			return models.EventBatch{}, fmt.Errorf("event type is required at index %d", index)
		}
		if event.AgentID == "" {
			event.AgentID = agentID
		} else if strings.TrimSpace(event.AgentID) != agentID {
			return models.EventBatch{}, fmt.Errorf("event agentId mismatch at index %d", index)
		}
		if event.Time.IsZero() {
			event.Time = batch.CreatedAt
		}
		if event.EventID == "" {
			event.EventID = fmt.Sprintf("evt-%s-%d-%d", agentID, batch.CreatedAt.UnixNano(), index)
		}
		events = append(events, event)
	}
	batch.AgentID = agentID
	batch.Events = events
	return batch, nil
}

func PrepareMetricBatch(batch models.MetricBatch) (models.MetricBatch, error) {
	agentID := strings.TrimSpace(batch.AgentID)
	if agentID == "" {
		return models.MetricBatch{}, fmt.Errorf("agentId is required")
	}
	if batch.CreatedAt.IsZero() {
		batch.CreatedAt = time.Now().UTC()
	}
	metrics := make([]models.MetricSample, 0, len(batch.Metrics))
	for index, metric := range batch.Metrics {
		if strings.TrimSpace(metric.Name) == "" {
			return models.MetricBatch{}, fmt.Errorf("metric name is required at index %d", index)
		}
		if metric.AgentID == "" {
			metric.AgentID = agentID
		} else if strings.TrimSpace(metric.AgentID) != agentID {
			return models.MetricBatch{}, fmt.Errorf("metric agentId mismatch at index %d", index)
		}
		if metric.Time.IsZero() {
			metric.Time = batch.CreatedAt
		}
		metrics = append(metrics, metric)
	}
	batch.AgentID = agentID
	batch.Metrics = metrics
	return batch, nil
}

func (s *Service) IngestEvents(batch models.EventBatch) int {
	normalized, err := PrepareEventBatch(batch)
	if err != nil {
		return 0
	}
	s.mu.Lock()
	s.events = append(s.events, normalized.Events...)
	if len(s.events) > s.maxEvents {
		s.events = append([]models.TrafficEvent(nil), s.events[len(s.events)-s.maxEvents:]...)
	}
	s.persistLocked()
	appendFn := s.appendEvents
	events := append([]models.TrafficEvent(nil), normalized.Events...)
	s.mu.Unlock()
	if s.appendEvents != nil {
		_ = appendFn(events)
	}
	return len(normalized.Events)
}

func (s *Service) IngestMetrics(batch models.MetricBatch) int {
	normalized, err := PrepareMetricBatch(batch)
	if err != nil {
		return 0
	}
	s.mu.Lock()
	s.metrics = append(s.metrics, normalized.Metrics...)
	if len(s.metrics) > s.maxMetrics {
		s.metrics = append([]models.MetricSample(nil), s.metrics[len(s.metrics)-s.maxMetrics:]...)
	}
	s.persistLocked()
	appendFn := s.appendMetrics
	metrics := append([]models.MetricSample(nil), normalized.Metrics...)
	s.mu.Unlock()
	if s.appendMetrics != nil {
		_ = appendFn(metrics)
	}
	return len(normalized.Metrics)
}

func (s *Service) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Snapshot{
		Events:  append([]models.TrafficEvent(nil), s.events...),
		Metrics: append([]models.MetricSample(nil), s.metrics...),
	}
}

func (s *Service) snapshotLocked() masterstate.IngestSnapshot {
	return masterstate.IngestSnapshot{
		Events:  append([]models.TrafficEvent(nil), s.events...),
		Metrics: append([]models.MetricSample(nil), s.metrics...),
	}
}

func (s *Service) persistLocked() {
	if s.persist == nil {
		return
	}
	_ = s.persist(s.snapshotLocked())
}
