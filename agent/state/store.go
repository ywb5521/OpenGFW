package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/apernet/OpenGFW/pkg/models"
)

var ErrNotFound = errors.New("state not found")

type Store interface {
	LoadIdentity(context.Context) (models.AgentIdentity, error)
	SaveIdentity(context.Context, models.AgentIdentity) error
	LoadActiveBundle(context.Context) (*models.Bundle, error)
	SaveActiveBundle(context.Context, models.Bundle) error
	LoadPendingIngest(context.Context) (PendingIngest, error)
	SavePendingIngest(context.Context, PendingIngest) error
}

type FileStore struct {
	dir string
}

type PendingIngest struct {
	Events  []models.TrafficEvent `json:"events"`
	Metrics []models.MetricSample `json:"metrics"`
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) LoadIdentity(_ context.Context) (models.AgentIdentity, error) {
	var identity models.AgentIdentity
	if err := s.loadJSON("identity.json", &identity); err != nil {
		return models.AgentIdentity{}, err
	}
	return identity, nil
}

func (s *FileStore) SaveIdentity(_ context.Context, identity models.AgentIdentity) error {
	return s.saveJSON("identity.json", identity)
}

func (s *FileStore) LoadActiveBundle(_ context.Context) (*models.Bundle, error) {
	var bundle models.Bundle
	if err := s.loadJSON("bundle.json", &bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func (s *FileStore) SaveActiveBundle(_ context.Context, bundle models.Bundle) error {
	return s.saveJSON("bundle.json", bundle)
}

func (s *FileStore) LoadPendingIngest(_ context.Context) (PendingIngest, error) {
	var pending PendingIngest
	if err := s.loadJSON("pending-ingest.json", &pending); err != nil {
		return PendingIngest{}, err
	}
	return pending, nil
}

func (s *FileStore) SavePendingIngest(_ context.Context, pending PendingIngest) error {
	return s.saveJSON("pending-ingest.json", pending)
}

func (s *FileStore) loadJSON(name string, dst any) error {
	path := filepath.Join(s.dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return json.Unmarshal(data, dst)
}

func (s *FileStore) saveJSON(name string, src any) error {
	path := filepath.Join(s.dir, name)
	data, err := json.MarshalIndent(src, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
