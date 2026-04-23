package release

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	masterstate "github.com/apernet/OpenGFW/master/state"
	"github.com/apernet/OpenGFW/pkg/models"
)

type ReleaseStore interface {
	UpsertReleaseArtifact(models.ReleaseArtifact) error
	ListReleaseArtifacts() ([]models.ReleaseArtifact, error)
	UpsertReleaseTask(models.ControlTask) error
	ListReleaseTasks(agentID string) ([]models.ControlTask, error)
	SaveSequence(name string, value uint64) error
}

type Service struct {
	mu        sync.RWMutex
	artifacts map[string]models.ReleaseArtifact
	tasks     map[string]map[string]*models.ControlTask
	seq       uint64
	persist   func(masterstate.ReleaseSnapshot) error
	store     ReleaseStore
}

func NewService() *Service {
	return NewServiceWithSnapshot(masterstate.ReleaseSnapshot{}, nil)
}

func NewServiceWithSnapshot(snapshot masterstate.ReleaseSnapshot, persist func(masterstate.ReleaseSnapshot) error) *Service {
	return NewServiceWithSnapshotAndStore(snapshot, persist, nil)
}

func NewServiceWithSnapshotAndStore(snapshot masterstate.ReleaseSnapshot, persist func(masterstate.ReleaseSnapshot) error, store ReleaseStore) *Service {
	if snapshot.Artifacts == nil {
		snapshot.Artifacts = make(map[string]models.ReleaseArtifact)
	}
	if snapshot.Tasks == nil {
		snapshot.Tasks = make(map[string]map[string]*models.ControlTask)
	}
	return &Service{
		artifacts: snapshot.Artifacts,
		tasks:     snapshot.Tasks,
		seq:       snapshot.Seq,
		persist:   persist,
		store:     store,
	}
}

func (s *Service) AddArtifact(artifact models.ReleaseArtifact) error {
	if artifact.Version == "" {
		return fmt.Errorf("release version is required")
	}
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifacts[artifact.Version] = artifact
	if err := s.syncArtifactLocked(artifact); err != nil {
		return err
	}
	return nil
}

func (s *Service) ListArtifacts() []models.ReleaseArtifact {
	result := s.QueryArtifacts(models.ReleaseQuery{})
	return result.Artifacts
}

func (s *Service) QueryArtifacts(query models.ReleaseQuery) models.ReleaseListResponse {
	artifacts := s.listAllArtifacts()
	filtered := make([]models.ReleaseArtifact, 0, len(artifacts))
	search := strings.ToLower(strings.TrimSpace(query.Search))
	for _, artifact := range artifacts {
		if query.Version != "" && artifact.Version != query.Version {
			continue
		}
		if search != "" && !matchesReleaseSearch(artifact, search) {
			continue
		}
		filtered = append(filtered, artifact)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Version < filtered[j].Version
	})
	total := len(filtered)
	offset := normalizeReleaseOffset(query.Offset)
	if offset >= len(filtered) {
		return models.ReleaseListResponse{Total: total}
	}
	if offset > 0 {
		filtered = filtered[offset:]
	}
	limit := normalizeReleaseLimit(query.Limit, 100)
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return models.ReleaseListResponse{
		Total:     total,
		Artifacts: filtered,
	}
}

func (s *Service) GetArtifact(version string) (models.ReleaseArtifact, bool) {
	for _, artifact := range s.listAllArtifacts() {
		if artifact.Version == version {
			return artifact, true
		}
	}
	return models.ReleaseArtifact{}, false
}

func (s *Service) listAllArtifacts() []models.ReleaseArtifact {
	if s.store != nil {
		if artifacts, err := s.store.ListReleaseArtifacts(); err == nil {
			return artifacts
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	artifacts := make([]models.ReleaseArtifact, 0, len(s.artifacts))
	for _, artifact := range s.artifacts {
		artifacts = append(artifacts, artifact)
	}
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Version < artifacts[j].Version
	})
	return artifacts
}

func (s *Service) Assign(version string, agentIDs []string) ([]models.ControlTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	artifact, ok := s.artifacts[version]
	if !ok {
		return nil, fmt.Errorf("release %q not found", version)
	}
	payload, err := json.Marshal(models.ReleaseTaskPayload{Artifact: artifact})
	if err != nil {
		return nil, err
	}

	tasks := make([]models.ControlTask, 0, len(agentIDs))
	for _, agentID := range agentIDs {
		if agentID == "" {
			continue
		}
		s.seq++
		task := &models.ControlTask{
			ID:        fmt.Sprintf("release-task-%d", s.seq),
			AgentID:   agentID,
			Type:      models.TaskTypeUpgradeAgent,
			Status:    models.TaskStatusPending,
			CreatedAt: time.Now().UTC(),
			Payload:   payload,
		}
		if _, ok := s.tasks[agentID]; !ok {
			s.tasks[agentID] = make(map[string]*models.ControlTask)
		}
		s.tasks[agentID][task.ID] = task
		tasks = append(tasks, *task)
		if err := s.syncTaskLocked(*task); err != nil {
			return nil, err
		}
	}
	return tasks, nil
}

func (s *Service) PendingTasks(agentID string) []models.ControlTask {
	return s.Tasks(agentID, models.TaskQuery{Status: string(models.TaskStatusPending)}).Tasks
}

func (s *Service) Tasks(agentID string, query models.TaskQuery) models.TaskListResponse {
	tasks := s.listAllTasks(agentID)
	filtered := filterReleaseTasks(tasks, query)
	total := len(filtered)
	offset := normalizeReleaseOffset(query.Offset)
	if offset >= len(filtered) {
		return models.TaskListResponse{Total: total}
	}
	if offset > 0 {
		filtered = filtered[offset:]
	}
	limit := normalizeReleaseLimit(query.Limit, 100)
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return models.TaskListResponse{
		Total: total,
		Tasks: filtered,
	}
}

func (s *Service) GetTask(agentID, taskID string) (models.ControlTask, bool) {
	for _, task := range s.listAllTasks(agentID) {
		if task.ID == taskID {
			return task, true
		}
	}
	return models.ControlTask{}, false
}

func (s *Service) listAllTasks(agentID string) []models.ControlTask {
	if s.store != nil {
		if tasks, err := s.store.ListReleaseTasks(agentID); err == nil {
			sort.Slice(tasks, func(i, j int) bool {
				return tasks[i].CreatedAt.Before(tasks[j].CreatedAt)
			})
			return tasks
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.tasks[agentID]) == 0 {
		return nil
	}
	tasks := make([]models.ControlTask, 0, len(s.tasks[agentID]))
	for _, task := range s.tasks[agentID] {
		tasks = append(tasks, *task)
	}
	sort.Slice(tasks, func(i, j int) bool {
		return tasks[i].CreatedAt.Before(tasks[j].CreatedAt)
	})
	return tasks
}

func (s *Service) AckTask(agentID, taskID string, ack models.AckTaskRequest) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	taskMap, ok := s.tasks[agentID]
	if !ok {
		return false
	}
	task, ok := taskMap[taskID]
	if !ok {
		return false
	}
	task.Status = ack.Status
	task.Message = ack.Message
	if err := s.syncTaskLocked(*task); err != nil {
		return false
	}
	return true
}

func collectPendingReleaseTaskList(tasks []models.ControlTask) []models.ControlTask {
	out := make([]models.ControlTask, 0, len(tasks))
	for _, task := range tasks {
		if task.Status != models.TaskStatusPending {
			continue
		}
		out = append(out, task)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func filterReleaseTasks(tasks []models.ControlTask, query models.TaskQuery) []models.ControlTask {
	out := make([]models.ControlTask, 0, len(tasks))
	for _, task := range tasks {
		if query.Status != "" && query.Status != "all" && string(task.Status) != query.Status {
			continue
		}
		if query.Type != "" && task.Type != query.Type {
			continue
		}
		out = append(out, task)
	}
	return out
}

func (s *Service) snapshotLocked() masterstate.ReleaseSnapshot {
	return masterstate.ReleaseSnapshot{
		Artifacts: cloneArtifactMap(s.artifacts),
		Tasks:     cloneReleaseTaskMap(s.tasks),
		Seq:       s.seq,
	}
}

func (s *Service) persistLocked() {
	if s.persist == nil {
		return
	}
	_ = s.persist(s.snapshotLocked())
}

func (s *Service) syncArtifactLocked(artifact models.ReleaseArtifact) error {
	if s.store != nil {
		return s.store.UpsertReleaseArtifact(artifact)
	}
	s.persistLocked()
	return nil
}

func (s *Service) syncTaskLocked(task models.ControlTask) error {
	if s.store != nil {
		if err := s.store.UpsertReleaseTask(task); err != nil {
			return err
		}
		return s.store.SaveSequence("releases", s.seq)
	}
	s.persistLocked()
	return nil
}

func cloneArtifactMap(src map[string]models.ReleaseArtifact) map[string]models.ReleaseArtifact {
	if len(src) == 0 {
		return make(map[string]models.ReleaseArtifact)
	}
	dst := make(map[string]models.ReleaseArtifact, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneReleaseTaskMap(src map[string]map[string]*models.ControlTask) map[string]map[string]*models.ControlTask {
	if len(src) == 0 {
		return make(map[string]map[string]*models.ControlTask)
	}
	dst := make(map[string]map[string]*models.ControlTask, len(src))
	for agentID, taskMap := range src {
		if len(taskMap) == 0 {
			dst[agentID] = make(map[string]*models.ControlTask)
			continue
		}
		dst[agentID] = make(map[string]*models.ControlTask, len(taskMap))
		for taskID, task := range taskMap {
			if task == nil {
				continue
			}
			cp := *task
			dst[agentID][taskID] = &cp
		}
	}
	return dst
}

func matchesReleaseSearch(artifact models.ReleaseArtifact, search string) bool {
	fields := []string{artifact.Version, artifact.DownloadURL, artifact.Checksum, artifact.Notes}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}
	return false
}

func normalizeReleaseLimit(limit int, fallback int) int {
	if limit <= 0 {
		return fallback
	}
	return limit
}

func normalizeReleaseOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}
