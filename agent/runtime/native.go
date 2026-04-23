package runtime

import (
	"context"
	"reflect"
	"sync"
	"time"

	bundlepkg "github.com/apernet/OpenGFW/pkg/bundle"
	"github.com/apernet/OpenGFW/pkg/models"
	opengfwcore "github.com/apernet/OpenGFW/pkg/opengfw"

	"github.com/apernet/OpenGFW/agent/report"
	"github.com/apernet/OpenGFW/engine"
	gfwio "github.com/apernet/OpenGFW/io"

	"go.uber.org/zap"
)

type NativeRuntime struct {
	logger      *zap.Logger
	collector   *report.Collector
	eventLogger *eventLogger

	mu           sync.RWMutex
	active       *models.Bundle
	status       models.RuntimeStatus
	started      bool
	rootCtx      context.Context
	rootCancel   context.CancelFunc
	engine       engine.Engine
	packetIO     gfwio.PacketIO
	engineCancel context.CancelFunc
	engineDone   chan struct{}
}

func NewNativeRuntime(logger *zap.Logger, collector *report.Collector) *NativeRuntime {
	if logger == nil {
		logger = zap.NewNop()
	}
	rt := &NativeRuntime{
		logger:    logger,
		collector: collector,
		status: models.RuntimeStatus{
			State:     models.RuntimeStateStopped,
			UpdatedAt: time.Now().UTC(),
		},
	}
	rt.eventLogger = newEventLogger(logger, collector, rt.currentBundleVersion, rt.currentProfile)
	return rt
}

func (r *NativeRuntime) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}
	r.rootCtx, r.rootCancel = context.WithCancel(ctx)
	r.started = true
	active := copyBundle(r.active)
	r.mu.Unlock()

	if active == nil {
		bundle := defaultTelemetryBundle()
		return r.startEngine(bundle)
	}
	return r.startEngine(*active)
}

func (r *NativeRuntime) Stop(ctx context.Context) error {
	r.mu.Lock()
	if !r.started {
		r.status.State = models.RuntimeStateStopped
		r.status.UpdatedAt = time.Now().UTC()
		r.status.Message = "runtime stopped"
		r.mu.Unlock()
		return nil
	}
	cancelRoot := r.rootCancel
	r.started = false
	r.rootCtx = nil
	r.rootCancel = nil
	r.mu.Unlock()

	if cancelRoot != nil {
		cancelRoot()
	}
	if err := r.stopEngine(ctx); err != nil {
		return err
	}
	r.updateStatus(models.RuntimeStateStopped, r.currentBundleVersion(), "runtime stopped")
	return nil
}

func (r *NativeRuntime) ApplyBundle(ctx context.Context, bundle models.Bundle) error {
	bundle = opengfwcore.MergeWithDefaultTelemetry(bundle)
	bundle = bundlepkg.Normalize(bundle)
	if err := bundlepkg.Validate(bundle); err != nil {
		r.setError(bundle.Version, err)
		return err
	}

	r.mu.RLock()
	started := r.started
	active := copyBundle(r.active)
	currentEngine := r.engine
	currentPacketIO := r.packetIO
	r.mu.RUnlock()

	if !started {
		r.mu.Lock()
		r.active = copyBundle(&bundle)
		r.status.State = models.RuntimeStateStopped
		r.status.BundleVersion = bundle.Version
		r.status.UpdatedAt = time.Now().UTC()
		r.status.Message = "bundle staged"
		r.mu.Unlock()
		return nil
	}

	if active != nil && currentEngine != nil && currentPacketIO != nil && reflect.DeepEqual(active.Runtime, bundle.Runtime) {
		rs, err := opengfwcore.CompileBundle(bundle, opengfwcore.CompileOptions{
			Logger:               r.eventLogger,
			ProtectedDialContext: currentPacketIO.ProtectedDialContext,
		})
		if err != nil {
			r.setError(bundle.Version, err)
			return err
		}
		if err := currentEngine.UpdateRuleset(rs); err != nil {
			r.setError(bundle.Version, err)
			return err
		}
		r.mu.Lock()
		r.active = copyBundle(&bundle)
		r.status.State = models.RuntimeStateRunning
		r.status.BundleVersion = bundle.Version
		r.status.UpdatedAt = time.Now().UTC()
		r.status.Message = "ruleset updated"
		r.mu.Unlock()
		return nil
	}

	if err := r.stopEngine(ctx); err != nil {
		r.setError(bundle.Version, err)
		return err
	}
	return r.startEngine(bundle)
}

func (r *NativeRuntime) Status() models.RuntimeStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

func (r *NativeRuntime) startEngine(bundle models.Bundle) error {
	r.mu.RLock()
	rootCtx := r.rootCtx
	started := r.started
	r.mu.RUnlock()

	if !started || rootCtx == nil {
		r.mu.Lock()
		r.active = copyBundle(&bundle)
		r.status.State = models.RuntimeStateStopped
		r.status.BundleVersion = bundle.Version
		r.status.UpdatedAt = time.Now().UTC()
		r.status.Message = "bundle staged"
		r.mu.Unlock()
		return nil
	}

	r.updateStatus(models.RuntimeStateStarting, bundle.Version, "starting engine")

	engineConfig, err := opengfwcore.BuildEngineConfig(bundle.Runtime, r.eventLogger)
	if err != nil {
		r.setError(bundle.Version, err)
		return err
	}

	rs, err := opengfwcore.CompileBundle(bundle, opengfwcore.CompileOptions{
		Logger:               r.eventLogger,
		ProtectedDialContext: engineConfig.IO.ProtectedDialContext,
	})
	if err != nil {
		_ = engineConfig.IO.Close()
		r.setError(bundle.Version, err)
		return err
	}
	engineConfig.Ruleset = rs

	en, err := engine.NewEngine(*engineConfig)
	if err != nil {
		_ = engineConfig.IO.Close()
		r.setError(bundle.Version, err)
		return err
	}

	engineCtx, cancel := context.WithCancel(rootCtx)
	done := make(chan struct{})

	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		cancel()
		_ = engineConfig.IO.Close()
		return context.Canceled
	}
	r.engine = en
	r.packetIO = engineConfig.IO
	r.engineCancel = cancel
	r.engineDone = done
	r.active = copyBundle(&bundle)
	r.status.State = models.RuntimeStateRunning
	r.status.BundleVersion = bundle.Version
	r.status.UpdatedAt = time.Now().UTC()
	r.status.Message = "engine running"
	r.mu.Unlock()

	go r.runEngine(engineCtx, en, engineConfig.IO, done)
	return nil
}

func (r *NativeRuntime) runEngine(ctx context.Context, en engine.Engine, packetIO gfwio.PacketIO, done chan struct{}) {
	defer close(done)

	err := en.Run(ctx)
	if closeErr := packetIO.Close(); closeErr != nil {
		r.logger.Error("failed to close packet io", zap.Error(closeErr))
	}

	r.mu.Lock()
	current := r.engineDone == done
	if current {
		r.engine = nil
		r.packetIO = nil
		r.engineCancel = nil
		r.engineDone = nil
		if err != nil && ctx.Err() == nil {
			r.status.State = models.RuntimeStateError
			r.status.UpdatedAt = time.Now().UTC()
			r.status.Message = err.Error()
		}
	}
	r.mu.Unlock()

	if err != nil && ctx.Err() == nil {
		r.logger.Error("runtime engine exited unexpectedly", zap.Error(err))
	}
}

func (r *NativeRuntime) stopEngine(ctx context.Context) error {
	r.mu.RLock()
	cancel := r.engineCancel
	done := r.engineDone
	r.mu.RUnlock()

	if cancel == nil || done == nil {
		return nil
	}
	cancel()

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	r.mu.Lock()
	r.engine = nil
	r.packetIO = nil
	r.engineCancel = nil
	r.engineDone = nil
	r.mu.Unlock()
	return nil
}

func (r *NativeRuntime) updateStatus(state models.RuntimeState, bundleVersion string, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.State = state
	r.status.BundleVersion = bundleVersion
	r.status.UpdatedAt = time.Now().UTC()
	r.status.Message = message
}

func (r *NativeRuntime) setError(bundleVersion string, err error) {
	r.updateStatus(models.RuntimeStateError, bundleVersion, err.Error())
}

func (r *NativeRuntime) currentBundleVersion() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return ""
	}
	return r.active.Version
}

func (r *NativeRuntime) currentProfile() models.TelemetryProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return models.TelemetryProfile{}
	}
	return r.active.Telemetry
}

func copyBundle(bundle *models.Bundle) *models.Bundle {
	if bundle == nil {
		return nil
	}
	cp := *bundle
	return &cp
}

func defaultTelemetryBundle() models.Bundle {
	return opengfwcore.DefaultTelemetryBundle("")
}

func defaultTelemetryAnalyzerNames() []string {
	analyzers := opengfwcore.DefaultAnalyzers()
	names := make([]string, 0, len(analyzers))
	for _, analyzer := range analyzers {
		if analyzer == nil {
			continue
		}
		names = append(names, analyzer.Name())
	}
	return names
}
