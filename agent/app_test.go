package agent

import (
	"context"
	"encoding/json"
	"testing"

	agentbundle "github.com/apernet/OpenGFW/agent/bundle"
	"github.com/apernet/OpenGFW/agent/control"
	"github.com/apernet/OpenGFW/agent/runtime"
	"github.com/apernet/OpenGFW/agent/state"
	"github.com/apernet/OpenGFW/pkg/models"
)

type fakeControlClient struct {
	pendingTasks []models.ControlTask
	heartbeats   []models.HeartbeatRequest
	acks         []struct {
		agentID string
		taskID  string
		req     models.AckTaskRequest
	}
}

func (c *fakeControlClient) Register(context.Context, models.RegistrationRequest) (models.RegistrationResponse, error) {
	return models.RegistrationResponse{}, nil
}

func (c *fakeControlClient) Heartbeat(_ context.Context, req models.HeartbeatRequest) (models.HeartbeatResponse, error) {
	c.heartbeats = append(c.heartbeats, req)
	return models.HeartbeatResponse{}, nil
}

func (c *fakeControlClient) PendingTasks(context.Context, string) ([]models.ControlTask, error) {
	return append([]models.ControlTask(nil), c.pendingTasks...), nil
}

func (c *fakeControlClient) AckTask(_ context.Context, agentID, taskID string, req models.AckTaskRequest) error {
	c.acks = append(c.acks, struct {
		agentID string
		taskID  string
		req     models.AckTaskRequest
	}{agentID: agentID, taskID: taskID, req: req})
	return nil
}

func (c *fakeControlClient) UploadEvents(context.Context, models.EventBatch) error {
	return nil
}

func (c *fakeControlClient) UploadMetrics(context.Context, models.MetricBatch) error {
	return nil
}

func TestFetchTasksSendsHeartbeatAfterBundleApply(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	if err != nil {
		t.Fatalf("create state store failed: %v", err)
	}
	bundles, err := agentbundle.NewManager(context.Background(), store)
	if err != nil {
		t.Fatalf("create bundle manager failed: %v", err)
	}

	bundle := models.Bundle{
		Version: "bundle-v1",
		Rules: []models.RuleSpec{
			{
				Name:   "allow-all",
				Action: "allow",
				Expr:   "true",
			},
		},
	}
	payload, err := json.Marshal(models.BundleTaskPayload{Bundle: bundle})
	if err != nil {
		t.Fatalf("marshal payload failed: %v", err)
	}

	client := &fakeControlClient{
		pendingTasks: []models.ControlTask{
			{
				ID:      "bundle-task-1",
				AgentID: "agent-1",
				Type:    models.TaskTypeApplyBundle,
				Payload: payload,
			},
		},
	}

	app := NewApp(
		Config{
			Name:         "edge-1",
			Hostname:     "edge-1-host",
			AgentVersion: "test-agent",
		},
		nil,
		store,
		client,
		bundles,
		runtime.NewStubRuntime(),
		nil,
		nil,
	)

	if err := app.fetchTasks(context.Background(), "agent-1"); err != nil {
		t.Fatalf("fetch tasks failed: %v", err)
	}
	if len(client.heartbeats) != 1 {
		t.Fatalf("expected 1 post-task heartbeat, got %d", len(client.heartbeats))
	}
	if client.heartbeats[0].AgentID != "agent-1" {
		t.Fatalf("unexpected heartbeat agent id: %+v", client.heartbeats[0])
	}
	if client.heartbeats[0].BundleVersion != "bundle-v1" {
		t.Fatalf("expected heartbeat bundle version bundle-v1, got %+v", client.heartbeats[0])
	}
	if len(client.acks) != 1 || client.acks[0].req.Status != models.TaskStatusSuccess {
		t.Fatalf("unexpected task ack records: %+v", client.acks)
	}
}

var _ control.Client = (*fakeControlClient)(nil)
