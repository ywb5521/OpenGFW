package report

import (
	"context"
	"testing"

	"github.com/apernet/OpenGFW/agent/state"
	"github.com/apernet/OpenGFW/pkg/models"
)

func TestCollectorDrainsAndRequeues(t *testing.T) {
	collector := NewCollector(16)
	collector.Emit(models.TrafficEvent{Type: "rule_hit"})
	collector.AddMetric(models.MetricSample{Name: "rule_hits_total", Value: 1})

	eventBatch := collector.DrainEvents("agent-1", 10)
	if got := len(eventBatch.Events); got != 1 {
		t.Fatalf("expected 1 event, got %d", got)
	}

	metricBatch := collector.DrainMetrics("agent-1", 10)
	if got := len(metricBatch.Metrics); got != 1 {
		t.Fatalf("expected 1 metric, got %d", got)
	}

	collector.RequeueEvents(eventBatch)
	collector.RequeueMetrics(metricBatch)
	events, metrics := collector.Pending()
	if events != 1 || metrics != 1 {
		t.Fatalf("expected pending events=1 metrics=1, got %d %d", events, metrics)
	}
}

func TestCollectorPersistsPendingIngest(t *testing.T) {
	store, err := state.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("create file store failed: %v", err)
	}
	collector := NewCollector(0, store)
	collector.Emit(models.TrafficEvent{EventID: "evt-9", Type: "rule_hit"})
	collector.AddMetric(models.MetricSample{Name: "rule_hits_total", Value: 1})

	pending, err := store.LoadPendingIngest(context.Background())
	if err != nil {
		t.Fatalf("load pending ingest failed: %v", err)
	}
	if len(pending.Events) != 1 || len(pending.Metrics) != 1 {
		t.Fatalf("unexpected persisted pending ingest: %+v", pending)
	}

	restored := NewCollector(0, store)
	events, metrics := restored.Pending()
	if events != 1 || metrics != 1 {
		t.Fatalf("expected restored pending events=1 metrics=1, got %d %d", events, metrics)
	}
}
