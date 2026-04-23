package state

import (
	"testing"
	"time"

	"github.com/apernet/OpenGFW/pkg/models"
)

func TestFileStoreRoundTrip(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	nodeSnapshot := NodeSnapshot{
		Nodes: map[string]*models.AgentNode{
			"agent-1": {
				ID:         "agent-1",
				Name:       "edge-1",
				Status:     models.AgentStatusOnline,
				LastSeenAt: time.Now().UTC(),
			},
		},
		Bootstrap: map[string]string{"token": "agent-1"},
		Seq:       7,
	}
	if err := store.SaveNodes(nodeSnapshot); err != nil {
		t.Fatalf("failed to save nodes: %v", err)
	}
	loadedNodes, err := store.LoadNodes()
	if err != nil {
		t.Fatalf("failed to load nodes: %v", err)
	}
	if loadedNodes.Seq != nodeSnapshot.Seq || loadedNodes.Nodes["agent-1"].Name != "edge-1" {
		t.Fatalf("unexpected loaded nodes: %+v", loadedNodes)
	}

	policySnapshot := PolicySnapshot{
		Bundles: map[string]models.Bundle{"v1": {Version: "v1"}},
		Tasks: map[string]map[string]*models.ControlTask{
			"agent-1": {
				"task-1": {ID: "task-1", AgentID: "agent-1"},
			},
		},
		Seq: 3,
	}
	if err := store.SavePolicies(policySnapshot); err != nil {
		t.Fatalf("failed to save policies: %v", err)
	}
	loadedPolicies, err := store.LoadPolicies()
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}
	if loadedPolicies.Seq != 3 || loadedPolicies.Bundles["v1"].Version != "v1" {
		t.Fatalf("unexpected loaded policies: %+v", loadedPolicies)
	}

	ingestSnapshot := IngestSnapshot{
		Events:  []models.TrafficEvent{{AgentID: "agent-1", Type: "rule_hit"}},
		Metrics: []models.MetricSample{{Name: "streams_total", Value: 1}},
	}
	if err := store.SaveIngest(ingestSnapshot); err != nil {
		t.Fatalf("failed to save ingest: %v", err)
	}
	loadedIngest, err := store.LoadIngest()
	if err != nil {
		t.Fatalf("failed to load ingest: %v", err)
	}
	if len(loadedIngest.Events) != 1 || len(loadedIngest.Metrics) != 1 {
		t.Fatalf("unexpected loaded ingest: %+v", loadedIngest)
	}
}
