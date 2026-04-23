package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	agentbundle "github.com/apernet/OpenGFW/agent/bundle"
	"github.com/apernet/OpenGFW/agent/control"
	"github.com/apernet/OpenGFW/agent/report"
	"github.com/apernet/OpenGFW/agent/runtime"
	"github.com/apernet/OpenGFW/agent/state"
	"github.com/apernet/OpenGFW/agent/upgrade"
	"github.com/apernet/OpenGFW/pkg/models"

	"go.uber.org/zap"
)

type Config struct {
	Name              string
	Hostname          string
	ManagementIP      string
	AgentVersion      string
	BootstrapToken    string
	ServiceName       string
	InstalledBinary   string
	Labels            []string
	Capabilities      []string
	Metadata          map[string]string
	HeartbeatInterval time.Duration
	FlushInterval     time.Duration
	EventBatchSize    int
	MetricBatchSize   int
}

type App struct {
	cfg           Config
	logger        *zap.Logger
	stateStore    state.Store
	controlClient control.Client
	bundles       *agentbundle.Manager
	runtime       runtime.Runtime
	collector     *report.Collector
	upgrader      *upgrade.Stager
}

func NewApp(cfg Config, logger *zap.Logger, stateStore state.Store, controlClient control.Client, bundles *agentbundle.Manager, runtime runtime.Runtime, collector *report.Collector, upgrader *upgrade.Stager) *App {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 15 * time.Second
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.EventBatchSize <= 0 {
		cfg.EventBatchSize = 256
	}
	if cfg.MetricBatchSize <= 0 {
		cfg.MetricBatchSize = 256
	}
	return &App{
		cfg:           cfg,
		logger:        logger,
		stateStore:    stateStore,
		controlClient: controlClient,
		bundles:       bundles,
		runtime:       runtime,
		collector:     collector,
		upgrader:      upgrader,
	}
}

func (a *App) Run(ctx context.Context) error {
	identity, err := a.register(ctx)
	if err != nil {
		return err
	}
	if active := a.bundles.Current(); active != nil {
		if err := a.runtime.ApplyBundle(ctx, *active); err != nil {
			return err
		}
	}
	if err := a.runtime.Start(ctx); err != nil {
		return err
	}
	defer a.runtime.Stop(context.Background())

	if err := a.sync(ctx, identity.AgentID); err != nil {
		a.logger.Warn("initial sync failed", zap.Error(err))
	}

	heartbeatTicker := time.NewTicker(a.cfg.HeartbeatInterval)
	defer heartbeatTicker.Stop()
	flushTicker := time.NewTicker(a.cfg.FlushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeatTicker.C:
			if err := a.sendHeartbeat(ctx, identity.AgentID); err != nil {
				a.logger.Warn("heartbeat failed", zap.Error(err))
				continue
			}
			if err := a.fetchTasks(ctx, identity.AgentID); err != nil {
				a.logger.Warn("task fetch failed", zap.Error(err))
			}
		case <-flushTicker.C:
			if err := a.flush(ctx, identity.AgentID); err != nil {
				a.logger.Warn("flush failed", zap.Error(err))
			}
		}
	}
}

func (a *App) sync(ctx context.Context, agentID string) error {
	if err := a.sendHeartbeat(ctx, agentID); err != nil {
		return err
	}
	if err := a.fetchTasks(ctx, agentID); err != nil {
		return err
	}
	return a.flush(ctx, agentID)
}

func (a *App) register(ctx context.Context) (models.AgentIdentity, error) {
	identity, err := a.stateStore.LoadIdentity(ctx)
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return models.AgentIdentity{}, err
	}
	req := models.RegistrationRequest{
		AgentID:        identity.AgentID,
		BootstrapToken: identity.BootstrapToken,
		Name:           a.cfg.Name,
		Hostname:       a.cfg.Hostname,
		ManagementIP:   a.cfg.ManagementIP,
		AgentVersion:   a.cfg.AgentVersion,
		Labels:         a.cfg.Labels,
		Capabilities:   a.cfg.Capabilities,
		Metadata:       a.cfg.Metadata,
	}
	if req.BootstrapToken == "" {
		req.BootstrapToken = a.cfg.BootstrapToken
	}
	resp, err := a.controlClient.Register(ctx, req)
	if err != nil {
		return models.AgentIdentity{}, err
	}
	identity.AgentID = resp.AgentID
	identity.BootstrapToken = ""
	identity.RegisteredAt = resp.RegisteredAt
	if err := a.stateStore.SaveIdentity(ctx, identity); err != nil {
		return models.AgentIdentity{}, err
	}
	return identity, nil
}

func (a *App) sendHeartbeat(ctx context.Context, agentID string) error {
	req := models.HeartbeatRequest{
		AgentID:       agentID,
		Name:          a.cfg.Name,
		Hostname:      a.cfg.Hostname,
		AgentVersion:  a.cfg.AgentVersion,
		BundleVersion: a.currentBundleVersion(),
		Runtime:       a.runtime.Status(),
		Capabilities:  a.cfg.Capabilities,
		Metadata:      a.cfg.Metadata,
	}
	_, err := a.controlClient.Heartbeat(ctx, req)
	return err
}

func (a *App) fetchTasks(ctx context.Context, agentID string) error {
	tasks, err := a.controlClient.PendingTasks(ctx, agentID)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		ack := a.handleTask(ctx, task)
		if ack.Status == models.TaskStatusSuccess && task.Type == models.TaskTypeApplyBundle {
			if err := a.sendHeartbeat(ctx, agentID); err != nil {
				a.logger.Warn("post-task heartbeat failed", zap.String("taskId", task.ID), zap.Error(err))
			}
		}
		if err := a.controlClient.AckTask(ctx, agentID, task.ID, ack); err != nil {
			a.logger.Warn("failed to ack task", zap.String("taskId", task.ID), zap.Error(err))
		}
	}
	return nil
}

func (a *App) handleTask(ctx context.Context, task models.ControlTask) models.AckTaskRequest {
	switch task.Type {
	case models.TaskTypeApplyBundle:
		var payload models.BundleTaskPayload
		if err := json.Unmarshal(task.Payload, &payload); err != nil {
			return models.AckTaskRequest{Status: models.TaskStatusFailed, Message: err.Error()}
		}
		if err := a.bundles.Apply(ctx, payload.Bundle); err != nil {
			return models.AckTaskRequest{Status: models.TaskStatusFailed, Message: err.Error()}
		}
		if err := a.runtime.ApplyBundle(ctx, payload.Bundle); err != nil {
			return models.AckTaskRequest{Status: models.TaskStatusFailed, Message: err.Error()}
		}
		return models.AckTaskRequest{
			Status:  models.TaskStatusSuccess,
			Message: "bundle applied",
		}
	case models.TaskTypeUpgradeAgent:
		if a.upgrader == nil {
			return models.AckTaskRequest{
				Status:  models.TaskStatusFailed,
				Message: "upgrade stager not configured",
			}
		}
		var payload models.ReleaseTaskPayload
		if err := json.Unmarshal(task.Payload, &payload); err != nil {
			return models.AckTaskRequest{Status: models.TaskStatusFailed, Message: err.Error()}
		}
		path, err := a.upgrader.Stage(ctx, payload.Artifact)
		if err != nil {
			return models.AckTaskRequest{Status: models.TaskStatusFailed, Message: err.Error()}
		}
		if a.cfg.ServiceName != "" && a.cfg.InstalledBinary != "" {
			if err := a.upgrader.ScheduleApplyVersion(path, a.cfg.InstalledBinary, a.cfg.ServiceName, payload.Artifact.Version); err != nil {
				return models.AckTaskRequest{Status: models.TaskStatusFailed, Message: err.Error()}
			}
			return models.AckTaskRequest{
				Status:  models.TaskStatusSuccess,
				Message: "artifact staged and restart scheduled",
			}
		}
		return models.AckTaskRequest{
			Status:  models.TaskStatusSuccess,
			Message: "artifact staged at " + path + "; restart target not configured",
		}
	default:
		return models.AckTaskRequest{
			Status:  models.TaskStatusFailed,
			Message: "unsupported task type",
		}
	}
}

func (a *App) flush(ctx context.Context, agentID string) error {
	eventBatch := a.collector.DrainEvents(agentID, a.cfg.EventBatchSize)
	if len(eventBatch.Events) > 0 {
		if err := a.controlClient.UploadEvents(ctx, eventBatch); err != nil {
			a.collector.RequeueEvents(eventBatch)
			return err
		}
	}

	metricBatch := a.collector.DrainMetrics(agentID, a.cfg.MetricBatchSize)
	if len(metricBatch.Metrics) > 0 {
		if err := a.controlClient.UploadMetrics(ctx, metricBatch); err != nil {
			a.collector.RequeueMetrics(metricBatch)
			return err
		}
	}
	return nil
}

func (a *App) currentBundleVersion() string {
	active := a.bundles.Current()
	if active == nil {
		return ""
	}
	return active.Version
}
