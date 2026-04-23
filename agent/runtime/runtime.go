package runtime

import (
	"context"
	"sync"
	"time"

	bundlepkg "github.com/apernet/OpenGFW/pkg/bundle"
	"github.com/apernet/OpenGFW/pkg/models"
)

type Runtime interface {
	Start(context.Context) error
	Stop(context.Context) error
	ApplyBundle(context.Context, models.Bundle) error
	Status() models.RuntimeStatus
}

type StubRuntime struct {
	mu     sync.RWMutex
	active *models.Bundle
	status models.RuntimeStatus
}

func NewStubRuntime() *StubRuntime {
	return &StubRuntime{
		status: models.RuntimeStatus{
			State:     models.RuntimeStateStopped,
			UpdatedAt: time.Now().UTC(),
		},
	}
}

func (r *StubRuntime) Start(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.State = models.RuntimeStateRunning
	r.status.UpdatedAt = time.Now().UTC()
	r.status.Message = "stub runtime running"
	return nil
}

func (r *StubRuntime) Stop(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.State = models.RuntimeStateStopped
	r.status.UpdatedAt = time.Now().UTC()
	r.status.Message = "stub runtime stopped"
	return nil
}

func (r *StubRuntime) ApplyBundle(_ context.Context, bundle models.Bundle) error {
	bundle = bundlepkg.Normalize(bundle)
	if err := bundlepkg.Validate(bundle); err != nil {
		r.mu.Lock()
		r.status.State = models.RuntimeStateError
		r.status.UpdatedAt = time.Now().UTC()
		r.status.Message = err.Error()
		r.mu.Unlock()
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = &bundle
	r.status.State = models.RuntimeStateRunning
	r.status.BundleVersion = bundle.Version
	r.status.UpdatedAt = time.Now().UTC()
	r.status.Message = "bundle applied"
	return nil
}

func (r *StubRuntime) Status() models.RuntimeStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}
