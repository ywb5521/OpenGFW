package node

import (
	"testing"
	"time"

	"github.com/apernet/OpenGFW/pkg/models"
)

func TestBootstrapReservationAndRegister(t *testing.T) {
	svc := NewService()
	node, token, err := svc.ReserveBootstrap(models.BootstrapInstallRequest{
		Name:     "edge-1",
		Hostname: "edge-1-host",
	})
	if err != nil {
		t.Fatalf("reserve bootstrap failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected bootstrap token")
	}
	if node.Status != models.AgentStatusPending {
		t.Fatalf("expected pending node, got %s", node.Status)
	}

	registered, err := svc.Register(models.RegistrationRequest{
		BootstrapToken: token,
		Name:           "edge-1",
		Hostname:       "edge-1-host",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if registered.ID != node.ID {
		t.Fatalf("expected node id %s, got %s", node.ID, registered.ID)
	}
	if registered.Status != models.AgentStatusOnline {
		t.Fatalf("expected online node, got %s", registered.Status)
	}
	if persistedToken, ok := svc.BootstrapTokenForNode(node.ID); !ok || persistedToken != token {
		t.Fatalf("expected bootstrap token to remain bound to node, got %q ok=%v", persistedToken, ok)
	}
}

func TestEnsureBootstrapTokenForExistingNode(t *testing.T) {
	svc := NewService()
	registered, err := svc.Register(models.RegistrationRequest{
		AgentID: "agent-1",
		Name:    "edge-1",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	token, err := svc.EnsureBootstrapToken(registered.ID)
	if err != nil {
		t.Fatalf("ensure bootstrap token failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected bootstrap token")
	}
	sameToken, err := svc.EnsureBootstrapToken(registered.ID)
	if err != nil {
		t.Fatalf("ensure bootstrap token repeat failed: %v", err)
	}
	if sameToken != token {
		t.Fatalf("expected stable bootstrap token, got %q want %q", sameToken, token)
	}
}

func TestDeleteNodeRemovesBootstrapToken(t *testing.T) {
	svc := NewService()
	node, token, err := svc.ReserveBootstrap(models.BootstrapInstallRequest{Name: "edge-1"})
	if err != nil {
		t.Fatalf("reserve bootstrap failed: %v", err)
	}
	if err := svc.Delete(node.ID); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, ok := svc.Get(node.ID); ok {
		t.Fatalf("expected node %s to be removed", node.ID)
	}
	if _, ok := svc.LookupBootstrapToken(token); ok {
		t.Fatalf("expected bootstrap token %s to be removed", token)
	}
}

func TestStaleNodeIsReportedOfflineUntilNextHeartbeat(t *testing.T) {
	svc := NewService()
	baseTime := time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC)
	svc.nowFunc = func() time.Time { return baseTime }

	registered, err := svc.Register(models.RegistrationRequest{
		AgentID: "agent-1",
		Name:    "edge-1",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if registered.Status != models.AgentStatusOnline {
		t.Fatalf("expected online after register, got %s", registered.Status)
	}

	svc.nowFunc = func() time.Time { return baseTime.Add(61 * time.Second) }
	nodeInfo, ok := svc.Get("agent-1")
	if !ok {
		t.Fatal("expected node to exist")
	}
	if nodeInfo.Status != models.AgentStatusOffline {
		t.Fatalf("expected stale node to be reported offline, got %s", nodeInfo.Status)
	}

	svc.nowFunc = func() time.Time { return baseTime.Add(70 * time.Second) }
	nodeInfo, err = svc.Heartbeat(models.HeartbeatRequest{
		AgentID: "agent-1",
	})
	if err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}
	if nodeInfo.Status != models.AgentStatusOnline {
		t.Fatalf("expected node to return online after heartbeat, got %s", nodeInfo.Status)
	}
}
