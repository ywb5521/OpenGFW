package bundle

import (
	"context"
	"sync"

	bundlepkg "github.com/apernet/OpenGFW/pkg/bundle"
	"github.com/apernet/OpenGFW/pkg/models"

	"github.com/apernet/OpenGFW/agent/state"
)

type Manager struct {
	mu      sync.RWMutex
	store   state.Store
	current *models.Bundle
}

func NewManager(ctx context.Context, store state.Store) (*Manager, error) {
	manager := &Manager{store: store}
	bundle, err := store.LoadActiveBundle(ctx)
	if err != nil && err != state.ErrNotFound {
		return nil, err
	}
	if bundle != nil {
		manager.current = bundle
	}
	return manager, nil
}

func (m *Manager) Current() *models.Bundle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		return nil
	}
	cp := *m.current
	return &cp
}

func (m *Manager) Apply(ctx context.Context, bundle models.Bundle) error {
	bundle = bundlepkg.Normalize(bundle)
	if err := bundlepkg.Validate(bundle); err != nil {
		return err
	}
	if err := m.store.SaveActiveBundle(ctx, bundle); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = &bundle
	return nil
}
