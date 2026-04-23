package report

import (
	"testing"
	"time"

	"github.com/apernet/OpenGFW/master/ingest"
	"github.com/apernet/OpenGFW/master/node"
	"github.com/apernet/OpenGFW/pkg/models"
)

type fakeQueryStore struct{}

func (s fakeQueryStore) QuerySummary() (models.ReportSummary, error) {
	return models.ReportSummary{
		EventCount:       7,
		SuspiciousEvents: 3,
		EventsByType:     map[string]int{"rule_hit": 5},
		EventsByProtocol: map[string]int{"tcp": 7},
		MetricCount:      2,
		MetricsByName:    map[string]int{"rule_hits_total": 2},
	}, nil
}

func (s fakeQueryStore) QueryEvents(query models.EventQuery) (models.EventQueryResult, error) {
	return models.EventQueryResult{
		Total: 1,
		Events: []models.TrafficEvent{
			{AgentID: "agent-db", Type: "rule_hit", Time: time.Now().UTC()},
		},
	}, nil
}

func (s fakeQueryStore) QueryRules(query models.TimeRangeQuery) ([]models.RuleReportItem, error) {
	return []models.RuleReportItem{{RuleName: "db-rule", Hits: 9}}, nil
}

func (s fakeQueryStore) QueryProtocols(query models.TimeRangeQuery) ([]models.ProtocolReportItem, error) {
	return []models.ProtocolReportItem{{Protocol: "tcp", Events: 9}}, nil
}

func (s fakeQueryStore) QueryNodeStats(query models.TimeRangeQuery) ([]models.NodeReportItem, error) {
	return []models.NodeReportItem{{AgentID: "agent-1", Events: 9, RuleHits: 4}}, nil
}

func (s fakeQueryStore) QueryMetrics(query models.MetricQuery) (models.MetricQueryResult, error) {
	return models.MetricQueryResult{
		Total:   1,
		Metrics: []models.MetricReportItem{{Name: "db_metric", Value: 2}},
	}, nil
}

func (s fakeQueryStore) QueryTrafficSeries(query models.TimeRangeQuery) (models.TimeSeriesResponse, error) {
	return models.TimeSeriesResponse{
		Buckets: []models.TimeSeriesBucket{
			{Timestamp: time.Now().UTC(), Events: 4, Suspicious: 1, RuleHits: 2},
		},
	}, nil
}

func TestServicePrefersQueryBackend(t *testing.T) {
	nodeSvc := node.NewService()
	_, err := nodeSvc.Register(models.RegistrationRequest{
		AgentID: "agent-1",
		Name:    "edge-1",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	svc := NewServiceWithQueries(nodeSvc, ingest.NewService(10, 10), fakeQueryStore{})

	summary := svc.Summary()
	if summary.EventCount != 7 || summary.Nodes != 1 {
		t.Fatalf("unexpected summary from query backend: %+v", summary)
	}

	events := svc.Events(models.EventQuery{})
	if events.Total != 1 || events.Events[0].AgentID != "agent-db" {
		t.Fatalf("unexpected events result: %+v", events)
	}

	rules := svc.Rules(models.TimeRangeQuery{})
	if len(rules) != 1 || rules[0].RuleName != "db-rule" {
		t.Fatalf("unexpected rules result: %+v", rules)
	}

	protocols := svc.Protocols(models.TimeRangeQuery{})
	if len(protocols) != 1 || protocols[0].Protocol != "tcp" {
		t.Fatalf("unexpected protocols result: %+v", protocols)
	}

	nodes := svc.Nodes(models.TimeRangeQuery{})
	if len(nodes) == 0 || nodes[0].AgentID != "agent-1" {
		t.Fatalf("unexpected nodes result: %+v", nodes)
	}

	metrics := svc.Metrics(models.MetricQuery{})
	if metrics.Total != 1 || metrics.Metrics[0].Name != "db_metric" {
		t.Fatalf("unexpected metrics result: %+v", metrics)
	}
}
