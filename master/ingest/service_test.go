package ingest

import (
	"testing"

	"github.com/apernet/OpenGFW/pkg/models"
)

func TestPrepareEventBatchBackfillsAgentAndTime(t *testing.T) {
	batch, err := PrepareEventBatch(models.EventBatch{
		AgentID: "agent-1",
		Events: []models.TrafficEvent{
			{Type: "rule_hit"},
		},
	})
	if err != nil {
		t.Fatalf("prepare event batch failed: %v", err)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(batch.Events))
	}
	if batch.Events[0].AgentID != "agent-1" {
		t.Fatalf("expected event agent id to be backfilled, got %+v", batch.Events[0])
	}
	if batch.Events[0].Time.IsZero() {
		t.Fatalf("expected event time to be backfilled, got %+v", batch.Events[0])
	}
	if batch.Events[0].EventID == "" {
		t.Fatalf("expected event id to be generated, got %+v", batch.Events[0])
	}
}

func TestPrepareMetricBatchBackfillsAgentAndTime(t *testing.T) {
	batch, err := PrepareMetricBatch(models.MetricBatch{
		AgentID: "agent-1",
		Metrics: []models.MetricSample{
			{Name: "streams_total", Value: 1},
		},
	})
	if err != nil {
		t.Fatalf("prepare metric batch failed: %v", err)
	}
	if len(batch.Metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(batch.Metrics))
	}
	if batch.Metrics[0].AgentID != "agent-1" {
		t.Fatalf("expected metric agent id to be backfilled, got %+v", batch.Metrics[0])
	}
	if batch.Metrics[0].Time.IsZero() {
		t.Fatalf("expected metric time to be backfilled, got %+v", batch.Metrics[0])
	}
}

func TestPrepareEventBatchRejectsAgentMismatch(t *testing.T) {
	_, err := PrepareEventBatch(models.EventBatch{
		AgentID: "agent-1",
		Events: []models.TrafficEvent{
			{AgentID: "agent-2", Type: "rule_hit"},
		},
	})
	if err == nil {
		t.Fatal("expected agent mismatch to fail")
	}
}
