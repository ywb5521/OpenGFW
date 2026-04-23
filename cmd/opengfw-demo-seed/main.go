package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	masterstate "github.com/apernet/OpenGFW/master/state"
	"github.com/apernet/OpenGFW/pkg/models"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	databaseURL := flag.String("database-url", "", "PostgreSQL database URL")
	flag.Parse()

	if *databaseURL == "" {
		log.Fatal("database-url is required")
	}

	ctx := context.Background()
	store, err := masterstate.NewPostgresStore(ctx, *databaseURL)
	if err != nil {
		log.Fatalf("init postgres store: %v", err)
	}
	defer store.Close()

	hasAdmin, err := store.HasAdminUsers()
	if err != nil {
		log.Fatalf("check admin users: %v", err)
	}
	if !hasAdmin {
		hash, err := bcrypt.GenerateFromPassword([]byte("OpenGFW123!"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("hash demo admin password: %v", err)
		}
		if _, err := store.BootstrapAdminUser("admin", string(hash)); err != nil {
			log.Fatalf("create demo admin user: %v", err)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)

	bundle := models.Bundle{
		Version:      "demo-bundle-2026-04-22",
		AgentVersion: "0.1.0",
		Telemetry: models.TelemetryProfile{
			Analyzers: []string{"dns", "tls", "http", "fet", "trojan"},
			Events: models.TelemetryEvents{
				RuleHit:     true,
				FlowSummary: true,
			},
		},
		Rules: []models.RuleSpec{
			{
				Name:   "block-malware-sni",
				Action: "block",
				Expr:   `tls.req.sni != nil && tls.req.sni == "malware.example"`,
			},
			{
				Name: "observe-fet",
				Log:  true,
				Expr: `fet.yes == true`,
			},
			{
				Name:   "block-ads-dns",
				Action: "modify",
				Modifier: &models.ModifierSpec{
					Name: "dns",
					Args: map[string]any{"a": "127.0.0.1"},
				},
				Expr: `proto == "udp" && dns.qr == true && dns.questions != nil`,
			},
		},
		CreatedAt: now.Add(-2 * time.Hour),
	}
	if err := store.UpsertPolicyBundle(bundle); err != nil {
		log.Fatalf("upsert bundle: %v", err)
	}

	releaseArtifact := models.ReleaseArtifact{
		Version:     "0.1.1-demo",
		DownloadURL: "https://downloads.example.local/opengfw-agent-0.1.1-demo",
		Checksum:    "sha256:3a5ecf9b4bd2057a4b0d94b6e1135fbdf72f3f04e6f7dacf6b61e4ccf7c8a1de",
		Notes:       "演示环境预发布包，包含控制台与主控联调能力。",
		CreatedAt:   now.Add(-90 * time.Minute),
	}
	if err := store.UpsertReleaseArtifact(releaseArtifact); err != nil {
		log.Fatalf("upsert release artifact: %v", err)
	}

	nodes := []models.AgentNode{
		{
			ID:            "agent-edge-01",
			Name:          "edge-gw-hk-01",
			Hostname:      "edge-gw-hk-01",
			ManagementIP:  "10.10.0.11",
			Labels:        []string{"edge", "hk", "production"},
			Status:        models.AgentStatusOnline,
			AgentVersion:  "0.1.0",
			BundleVersion: bundle.Version,
			LastSeenAt:    now.Add(-30 * time.Second),
			Capabilities:  []string{"nfqueue", "rule-runtime", "report-uploader"},
			Metadata:      map[string]string{"region": "hk", "role": "gateway"},
		},
		{
			ID:            "agent-edge-02",
			Name:          "edge-gw-sg-01",
			Hostname:      "edge-gw-sg-01",
			ManagementIP:  "10.10.0.21",
			Labels:        []string{"edge", "sg", "production"},
			Status:        models.AgentStatusOnline,
			AgentVersion:  "0.1.0",
			BundleVersion: bundle.Version,
			LastSeenAt:    now.Add(-55 * time.Second),
			Capabilities:  []string{"nfqueue", "rule-runtime", "report-uploader"},
			Metadata:      map[string]string{"region": "sg", "role": "gateway"},
		},
		{
			ID:            "agent-lab-01",
			Name:          "lab-node-01",
			Hostname:      "lab-node-01",
			ManagementIP:  "10.20.0.15",
			Labels:        []string{"lab", "staging"},
			Status:        models.AgentStatusPending,
			AgentVersion:  "0.1.0",
			BundleVersion: "",
			LastSeenAt:    now.Add(-18 * time.Minute),
			Capabilities:  []string{"rule-runtime"},
			Metadata:      map[string]string{"region": "lab", "role": "testbed"},
		},
	}
	for _, node := range nodes {
		if err := store.UpsertNode(node); err != nil {
			log.Fatalf("upsert node %s: %v", node.ID, err)
		}
	}
	if err := store.SaveSequence("nodes", uint64(len(nodes))); err != nil {
		log.Fatalf("save node sequence: %v", err)
	}

	bundlePayload, err := json.Marshal(models.BundleTaskPayload{Bundle: bundle})
	if err != nil {
		log.Fatalf("marshal bundle task payload: %v", err)
	}
	releasePayload, err := json.Marshal(models.ReleaseTaskPayload{Artifact: releaseArtifact})
	if err != nil {
		log.Fatalf("marshal release task payload: %v", err)
	}

	tasks := []models.ControlTask{
		{
			ID:        "bundle-task-demo-001",
			AgentID:   "agent-edge-01",
			Type:      models.TaskTypeApplyBundle,
			Status:    models.TaskStatusSuccess,
			CreatedAt: now.Add(-80 * time.Minute),
			Message:   "策略包已成功应用",
			Payload:   bundlePayload,
		},
		{
			ID:        "bundle-task-demo-002",
			AgentID:   "agent-edge-02",
			Type:      models.TaskTypeApplyBundle,
			Status:    models.TaskStatusPending,
			CreatedAt: now.Add(-10 * time.Minute),
			Message:   "等待节点拉取",
			Payload:   bundlePayload,
		},
		{
			ID:        "release-task-demo-001",
			AgentID:   "agent-lab-01",
			Type:      models.TaskTypeUpgradeAgent,
			Status:    models.TaskStatusPending,
			CreatedAt: now.Add(-5 * time.Minute),
			Message:   "等待实验节点升级",
			Payload:   releasePayload,
		},
	}

	for _, task := range tasks[:2] {
		if err := store.UpsertPolicyTask(task); err != nil {
			log.Fatalf("upsert policy task %s: %v", task.ID, err)
		}
	}
	if err := store.SaveSequence("policies", 2); err != nil {
		log.Fatalf("save policy sequence: %v", err)
	}
	if err := store.UpsertReleaseTask(tasks[2]); err != nil {
		log.Fatalf("upsert release task: %v", err)
	}
	if err := store.SaveSequence("releases", 1); err != nil {
		log.Fatalf("save release sequence: %v", err)
	}

	events := []models.TrafficEvent{
		{
			EventID:   "demo-event-001",
			AgentID:   "agent-edge-01",
			Time:      now.Add(-25 * time.Minute),
			Type:      "rule_hit",
			Proto:     "tcp",
			SrcIP:     "172.16.0.11",
			DstIP:     "45.67.12.8",
			SrcPort:   54231,
			DstPort:   443,
			RuleName:  "block-malware-sni",
			Action:    "block",
			Props:     map[string]any{"tls": map[string]any{"req": map[string]any{"sni": "malware.example"}}},
			Suspicion: 80,
			Tags:      []string{"ioc", "tls"},
			BundleVer: bundle.Version,
		},
		{
			EventID:   "demo-event-002",
			AgentID:   "agent-edge-01",
			Time:      now.Add(-22 * time.Minute),
			Type:      "suspicious_flow",
			Proto:     "tcp",
			SrcIP:     "172.16.0.44",
			DstIP:     "103.24.16.2",
			SrcPort:   51820,
			DstPort:   443,
			RuleName:  "observe-fet",
			Action:    "block",
			Props:     map[string]any{"fet": map[string]any{"yes": true}},
			Suspicion: 50,
			Tags:      []string{"fet", "encrypted"},
			BundleVer: bundle.Version,
		},
		{
			EventID:   "demo-event-003",
			AgentID:   "agent-edge-02",
			Time:      now.Add(-18 * time.Minute),
			Type:      "stream_action",
			Proto:     "udp",
			SrcIP:     "10.88.0.2",
			DstIP:     "8.8.8.8",
			SrcPort:   53001,
			DstPort:   53,
			RuleName:  "block-ads-dns",
			Action:    "modify",
			Props:     map[string]any{"dns": map[string]any{"qr": true}},
			BundleVer: bundle.Version,
		},
		{
			EventID:   "demo-event-004",
			AgentID:   "agent-edge-02",
			Time:      now.Add(-12 * time.Minute),
			Type:      "rule_hit",
			Proto:     "udp",
			SrcIP:     "10.88.0.2",
			DstIP:     "1.1.1.1",
			SrcPort:   53002,
			DstPort:   53,
			RuleName:  "block-ads-dns",
			Action:    "modify",
			Props:     map[string]any{"dns": map[string]any{"questions": []any{map[string]any{"name": "ads.example.com"}}}},
			Suspicion: 10,
			Tags:      []string{"dns"},
			BundleVer: bundle.Version,
		},
		{
			EventID:   "demo-event-005",
			AgentID:   "agent-edge-01",
			Time:      now.Add(-8 * time.Minute),
			Type:      "analyzer_error",
			Proto:     "tcp",
			SrcIP:     "172.16.0.88",
			DstIP:     "91.92.93.94",
			SrcPort:   49811,
			DstPort:   443,
			Props:     map[string]any{"name": "tls", "message": "unexpected handshake fragmentation"},
			BundleVer: bundle.Version,
		},
		{
			EventID:   "demo-event-006",
			AgentID:   "agent-edge-02",
			Time:      now.Add(-3 * time.Minute),
			Type:      "stream_action",
			Proto:     "tcp",
			SrcIP:     "10.0.2.15",
			DstIP:     "104.26.1.12",
			SrcPort:   43321,
			DstPort:   443,
			Action:    "allow",
			Props:     map[string]any{"tls": map[string]any{"req": map[string]any{"sni": "docs.example.dev"}}},
			BundleVer: bundle.Version,
		},
	}
	if err := store.AppendEvents(events); err != nil {
		log.Fatalf("append demo events: %v", err)
	}

	metrics := []models.MetricSample{
		{
			AgentID: "agent-edge-01",
			Time:    now.Add(-20 * time.Minute),
			Name:    "rule_hits_total",
			Value:   14,
			Labels:  map[string]string{"rule": "block-malware-sni"},
		},
		{
			AgentID: "agent-edge-02",
			Time:    now.Add(-20 * time.Minute),
			Name:    "streams_total",
			Value:   324,
			Labels:  map[string]string{"proto": "udp"},
		},
		{
			AgentID: "agent-edge-01",
			Time:    now.Add(-15 * time.Minute),
			Name:    "suspicious_flows_total",
			Value:   7,
			Labels:  map[string]string{"proto": "tcp"},
		},
		{
			AgentID: "agent-edge-02",
			Time:    now.Add(-10 * time.Minute),
			Name:    "stream_actions_total",
			Value:   211,
			Labels:  map[string]string{"proto": "tcp", "action": "allow"},
		},
		{
			AgentID: "agent-edge-01",
			Time:    now.Add(-5 * time.Minute),
			Name:    "rule_hits_total",
			Value:   3,
			Labels:  map[string]string{"rule": "observe-fet"},
		},
		{
			AgentID: "agent-edge-02",
			Time:    now.Add(-2 * time.Minute),
			Name:    "rule_hits_total",
			Value:   19,
			Labels:  map[string]string{"rule": "block-ads-dns"},
		},
	}
	if err := store.AppendMetrics(metrics); err != nil {
		log.Fatalf("append demo metrics: %v", err)
	}

	fmt.Println("demo data seeded into PostgreSQL")
	fmt.Println("demo admin credentials: admin / OpenGFW123!")
}
