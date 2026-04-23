package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/apernet/OpenGFW/pkg/models"
	"github.com/apernet/OpenGFW/pkg/transport"
)

type Client interface {
	Register(context.Context, models.RegistrationRequest) (models.RegistrationResponse, error)
	Heartbeat(context.Context, models.HeartbeatRequest) (models.HeartbeatResponse, error)
	PendingTasks(context.Context, string) ([]models.ControlTask, error)
	AckTask(context.Context, string, string, models.AckTaskRequest) error
	UploadEvents(context.Context, models.EventBatch) error
	UploadMetrics(context.Context, models.MetricBatch) error
}

type HTTPClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPClient(baseURL string, client *http.Client) *HTTPClient {
	if client == nil {
		client = &http.Client{}
	}
	return &HTTPClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  client,
	}
}

func (c *HTTPClient) Register(ctx context.Context, req models.RegistrationRequest) (models.RegistrationResponse, error) {
	var resp models.RegistrationResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/register", req, &resp)
	return resp, err
}

func (c *HTTPClient) Heartbeat(ctx context.Context, req models.HeartbeatRequest) (models.HeartbeatResponse, error) {
	var resp models.HeartbeatResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/heartbeat", req, &resp)
	return resp, err
}

func (c *HTTPClient) PendingTasks(ctx context.Context, agentID string) ([]models.ControlTask, error) {
	var resp models.TaskListResponse
	err := c.doJSON(ctx, http.MethodGet, "/api/v1/agents/"+agentID+"/tasks", nil, &resp)
	return resp.Tasks, err
}

func (c *HTTPClient) AckTask(ctx context.Context, agentID, taskID string, req models.AckTaskRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/tasks/"+taskID+"/ack", req, nil)
}

func (c *HTTPClient) UploadEvents(ctx context.Context, batch models.EventBatch) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/ingest/events", batch, nil)
}

func (c *HTTPClient) UploadMetrics(ctx context.Context, batch models.MetricBatch) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/ingest/metrics", batch, nil)
}

func (c *HTTPClient) doJSON(ctx context.Context, method, path string, reqBody any, respBody any) error {
	var body *bytes.Reader
	if reqBody == nil {
		body = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		var serverErr transport.ErrorResponse
		if err := transport.ReadJSONBody(resp.Body, &serverErr); err == nil && serverErr.Error != "" {
			return errors.New(serverErr.Error)
		}
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	if respBody == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return transport.ReadJSONBody(resp.Body, respBody)
}
