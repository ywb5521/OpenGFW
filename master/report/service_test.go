package report

import (
	"testing"
	"time"

	"github.com/apernet/OpenGFW/master/ingest"
	"github.com/apernet/OpenGFW/master/node"
	"github.com/apernet/OpenGFW/pkg/models"
)

func TestReportAggregations(t *testing.T) {
	nodes := node.NewService()
	registered, err := nodes.Register(models.RegistrationRequest{
		AgentID:  "agent-1",
		Name:     "edge-1",
		Hostname: "edge-1-host",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if registered.ID == "" {
		t.Fatal("expected registered node ID")
	}

	ing := ingest.NewService(100, 100)
	now := time.Now().UTC()
	ing.IngestEvents(models.EventBatch{
		AgentID: "agent-1",
		Events: []models.TrafficEvent{
			{Type: "rule_hit", RuleName: "block-ads", Proto: "tcp", Time: now},
			{Type: "suspicious_flow", RuleName: "block-ads", Proto: "tcp", Suspicion: 80, Time: now.Add(time.Second)},
		},
	})
	ing.IngestEvents(models.EventBatch{
		AgentID: "agent-2",
		Events: []models.TrafficEvent{
			{Type: "stream_action", Proto: "udp", Time: now.Add(2 * time.Second)},
		},
	})
	ing.IngestMetrics(models.MetricBatch{
		AgentID: "agent-1",
		Metrics: []models.MetricSample{
			{Name: "rule_hits_total", Value: 2, Time: now},
			{Name: "streams_total", Value: 1, Time: now.Add(time.Second)},
		},
	})

	svc := NewService(nodes, ing)

	summary := svc.Summary()
	if summary.EventCount != 3 {
		t.Fatalf("expected 3 events, got %d", summary.EventCount)
	}
	if summary.SuspiciousEvents != 1 {
		t.Fatalf("expected 1 suspicious event, got %d", summary.SuspiciousEvents)
	}

	events := svc.Events(models.EventQuery{AgentID: "agent-1"})
	if events.Total != 2 {
		t.Fatalf("expected 2 events for agent-1, got %d", events.Total)
	}
	paged := svc.Events(models.EventQuery{Limit: 1, Offset: 1})
	if paged.Total != 3 || len(paged.Events) != 1 {
		t.Fatalf("unexpected paged result: %+v", paged)
	}

	suspicious := svc.SuspiciousEvents(10)
	if suspicious.Total != 1 || len(suspicious.Events) != 1 {
		t.Fatalf("expected 1 suspicious event, got total=%d len=%d", suspicious.Total, len(suspicious.Events))
	}

	rules := svc.Rules(models.TimeRangeQuery{Limit: 10})
	if len(rules) != 1 || rules[0].RuleName != "block-ads" || rules[0].Hits != 1 {
		t.Fatalf("unexpected rule aggregation: %+v", rules)
	}

	protocols := svc.Protocols(models.TimeRangeQuery{})
	if len(protocols) != 2 {
		t.Fatalf("expected 2 protocol rows, got %d", len(protocols))
	}

	nodesReport := svc.Nodes(models.TimeRangeQuery{})
	if len(nodesReport) == 0 {
		t.Fatal("expected node report rows")
	}

	metrics := svc.Metrics(models.MetricQuery{Name: "rule_hits_total", Limit: 10})
	if metrics.Total != 1 || len(metrics.Metrics) != 1 {
		t.Fatalf("expected 1 metric row, got total=%d len=%d", metrics.Total, len(metrics.Metrics))
	}
}
