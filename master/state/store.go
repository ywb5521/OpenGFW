package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/apernet/OpenGFW/pkg/models"
)

var ErrNotFound = errors.New("state snapshot not found")

type NodeSnapshot struct {
	Nodes     map[string]*models.AgentNode `json:"nodes"`
	Bootstrap map[string]string            `json:"bootstrap"`
	Seq       uint64                       `json:"seq"`
}

type PolicySnapshot struct {
	Bundles map[string]models.Bundle                  `json:"bundles"`
	Tasks   map[string]map[string]*models.ControlTask `json:"tasks"`
	Seq     uint64                                    `json:"seq"`
}

type ReleaseSnapshot struct {
	Artifacts map[string]models.ReleaseArtifact         `json:"artifacts"`
	Tasks     map[string]map[string]*models.ControlTask `json:"tasks"`
	Seq       uint64                                    `json:"seq"`
}

type IngestSnapshot struct {
	Events  []models.TrafficEvent `json:"events"`
	Metrics []models.MetricSample `json:"metrics"`
}

type FileStore struct {
	dir string
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) LoadNodes() (NodeSnapshot, error) {
	var snapshot NodeSnapshot
	if err := s.load("nodes.json", &snapshot); err != nil {
		return NodeSnapshot{}, err
	}
	return snapshot, nil
}

func (s *FileStore) SaveNodes(snapshot NodeSnapshot) error {
	return s.save("nodes.json", snapshot)
}

func (s *FileStore) LoadPolicies() (PolicySnapshot, error) {
	var snapshot PolicySnapshot
	if err := s.load("policies.json", &snapshot); err != nil {
		return PolicySnapshot{}, err
	}
	return snapshot, nil
}

func (s *FileStore) SavePolicies(snapshot PolicySnapshot) error {
	return s.save("policies.json", snapshot)
}

func (s *FileStore) LoadReleases() (ReleaseSnapshot, error) {
	var snapshot ReleaseSnapshot
	if err := s.load("releases.json", &snapshot); err != nil {
		return ReleaseSnapshot{}, err
	}
	return snapshot, nil
}

func (s *FileStore) SaveReleases(snapshot ReleaseSnapshot) error {
	return s.save("releases.json", snapshot)
}

func (s *FileStore) LoadIngest() (IngestSnapshot, error) {
	var snapshot IngestSnapshot
	if err := s.load("ingest.json", &snapshot); err != nil {
		return IngestSnapshot{}, err
	}
	return snapshot, nil
}

func (s *FileStore) SaveIngest(snapshot IngestSnapshot) error {
	return s.save("ingest.json", snapshot)
}

func (s *FileStore) load(name string, dst any) error {
	data, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return json.Unmarshal(data, dst)
}

func (s *FileStore) save(name string, src any) error {
	data, err := json.MarshalIndent(src, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, name), data, 0o600)
}
