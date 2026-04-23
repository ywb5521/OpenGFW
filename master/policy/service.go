package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	masterstate "github.com/apernet/OpenGFW/master/state"
	bundlepkg "github.com/apernet/OpenGFW/pkg/bundle"
	"github.com/apernet/OpenGFW/pkg/models"
	opengfwcore "github.com/apernet/OpenGFW/pkg/opengfw"
)

const DefaultReportingBundleVersion = "system-default-reporting"

type PolicyStore interface {
	UpsertPolicyBundle(models.Bundle) error
	ListPolicyBundles() ([]models.Bundle, error)
	UpsertPolicyTask(models.ControlTask) error
	ListPolicyTasks(agentID string) ([]models.ControlTask, error)
	SaveSequence(name string, value uint64) error
}

type Service struct {
	mu      sync.RWMutex
	bundles map[string]models.Bundle
	tasks   map[string]map[string]*models.ControlTask
	seq     uint64
	persist func(masterstate.PolicySnapshot) error
	store   PolicyStore
}

func NewService() *Service {
	return NewServiceWithSnapshot(masterstate.PolicySnapshot{}, nil)
}

func NewServiceWithSnapshot(snapshot masterstate.PolicySnapshot, persist func(masterstate.PolicySnapshot) error) *Service {
	return NewServiceWithSnapshotAndStore(snapshot, persist, nil)
}

func NewServiceWithSnapshotAndStore(snapshot masterstate.PolicySnapshot, persist func(masterstate.PolicySnapshot) error, store PolicyStore) *Service {
	if snapshot.Bundles == nil {
		snapshot.Bundles = make(map[string]models.Bundle)
	}
	if snapshot.Tasks == nil {
		snapshot.Tasks = make(map[string]map[string]*models.ControlTask)
	}
	svc := &Service{
		bundles: snapshot.Bundles,
		tasks:   snapshot.Tasks,
		seq:     snapshot.Seq,
		persist: persist,
		store:   store,
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	_ = svc.ensureDefaultReportingBundleLocked()
	return svc
}

func defaultReportingBundle() models.Bundle {
	bundle := opengfwcore.DefaultTelemetryBundle(DefaultReportingBundleVersion)
	bundle.Readonly = true
	return bundle
}

func mergeBundleWithDefaultReporting(bundle models.Bundle) models.Bundle {
	return bundlepkg.Normalize(opengfwcore.MergeWithDefaultTelemetry(bundle))
}

func (s *Service) ensureDefaultReportingBundleLocked() error {
	bundle := bundlepkg.Normalize(defaultReportingBundle())
	if existing, ok := s.bundles[DefaultReportingBundleVersion]; ok {
		if existing.Readonly == bundle.Readonly &&
			reflect.DeepEqual(existing.Runtime, bundle.Runtime) &&
			reflect.DeepEqual(existing.Telemetry, bundle.Telemetry) &&
			len(existing.Rules) == 0 {
			return nil
		}
	}
	s.bundles[bundle.Version] = bundle
	return s.syncBundleLocked(bundle)
}

func (s *Service) AddBundle(bundle models.Bundle) error {
	if strings.TrimSpace(bundle.Version) == DefaultReportingBundleVersion {
		return fmt.Errorf("bundle %q is reserved", DefaultReportingBundleVersion)
	}
	bundle = bundlepkg.Normalize(bundle)
	bundle.Readonly = false
	if err := bundlepkg.Validate(bundle); err != nil {
		return err
	}
	if _, err := opengfwcore.CompileBundle(bundle, opengfwcore.CompileOptions{}); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundles[bundle.Version] = bundle
	if err := s.syncBundleLocked(bundle); err != nil {
		return err
	}
	return nil
}

func (s *Service) ListBundles() []models.Bundle {
	result := s.QueryBundles(models.BundleQuery{})
	return result.Bundles
}

func (s *Service) QueryBundles(query models.BundleQuery) models.BundleListResponse {
	bundles := s.listAllBundles()
	filtered := make([]models.Bundle, 0, len(bundles))
	search := strings.ToLower(strings.TrimSpace(query.Search))
	for _, bundle := range bundles {
		if query.Version != "" && bundle.Version != query.Version {
			continue
		}
		if search != "" && !matchesBundleSearch(bundle, search) {
			continue
		}
		filtered = append(filtered, bundle)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Readonly != filtered[j].Readonly {
			return filtered[i].Readonly
		}
		return filtered[i].Version < filtered[j].Version
	})
	total := len(filtered)
	offset := normalizePolicyOffset(query.Offset)
	if offset >= len(filtered) {
		return models.BundleListResponse{Total: total}
	}
	if offset > 0 {
		filtered = filtered[offset:]
	}
	limit := normalizePolicyLimit(query.Limit, 100)
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return models.BundleListResponse{
		Total:   total,
		Bundles: filtered,
	}
}

func (s *Service) GetBundle(version string) (models.Bundle, bool) {
	for _, bundle := range s.listAllBundles() {
		if bundle.Version == version {
			return bundle, true
		}
	}
	return models.Bundle{}, false
}

func (s *Service) listAllBundles() []models.Bundle {
	if s.store != nil {
		if bundles, err := s.store.ListPolicyBundles(); err == nil {
			return bundles
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	bundles := make([]models.Bundle, 0, len(s.bundles))
	for _, bundle := range s.bundles {
		bundles = append(bundles, bundle)
	}
	sort.Slice(bundles, func(i, j int) bool {
		return bundles[i].Version < bundles[j].Version
	})
	return bundles
}

func (s *Service) AssignBundle(version string, agentIDs []string) ([]models.ControlTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle, ok := s.bundles[version]
	if !ok {
		return nil, fmt.Errorf("bundle %q not found", version)
	}
	if version != DefaultReportingBundleVersion {
		bundle = mergeBundleWithDefaultReporting(bundle)
	}

	payload, err := json.Marshal(models.BundleTaskPayload{Bundle: bundle})
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
			ID:        fmt.Sprintf("bundle-task-%d", s.seq),
			AgentID:   agentID,
			Type:      models.TaskTypeApplyBundle,
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
	filtered := filterTasks(tasks, query)
	total := len(filtered)
	offset := normalizePolicyOffset(query.Offset)
	if offset >= len(filtered) {
		return models.TaskListResponse{Total: total}
	}
	if offset > 0 {
		filtered = filtered[offset:]
	}
	limit := normalizePolicyLimit(query.Limit, 100)
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
		if tasks, err := s.store.ListPolicyTasks(agentID); err == nil {
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

func collectPendingTasks(taskMap map[string]*models.ControlTask) []models.ControlTask {
	if len(taskMap) == 0 {
		return nil
	}
	tasks := make([]models.ControlTask, 0, len(taskMap))
	for _, task := range taskMap {
		if task.Status != models.TaskStatusPending {
			continue
		}
		tasks = append(tasks, *task)
	}
	sort.Slice(tasks, func(i, j int) bool {
		return tasks[i].CreatedAt.Before(tasks[j].CreatedAt)
	})
	return tasks
}

func collectPendingTaskList(tasks []models.ControlTask) []models.ControlTask {
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

func filterTasks(tasks []models.ControlTask, query models.TaskQuery) []models.ControlTask {
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

func (s *Service) snapshotLocked() masterstate.PolicySnapshot {
	return masterstate.PolicySnapshot{
		Bundles: cloneBundleMap(s.bundles),
		Tasks:   cloneTaskMap(s.tasks),
		Seq:     s.seq,
	}
}

func (s *Service) persistLocked() {
	if s.persist == nil {
		return
	}
	_ = s.persist(s.snapshotLocked())
}

func (s *Service) syncBundleLocked(bundle models.Bundle) error {
	if s.store != nil {
		return s.store.UpsertPolicyBundle(bundle)
	}
	s.persistLocked()
	return nil
}

func (s *Service) syncTaskLocked(task models.ControlTask) error {
	if s.store != nil {
		if err := s.store.UpsertPolicyTask(task); err != nil {
			return err
		}
		return s.store.SaveSequence("policies", s.seq)
	}
	s.persistLocked()
	return nil
}

func cloneBundleMap(src map[string]models.Bundle) map[string]models.Bundle {
	if len(src) == 0 {
		return make(map[string]models.Bundle)
	}
	dst := make(map[string]models.Bundle, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneTaskMap(src map[string]map[string]*models.ControlTask) map[string]map[string]*models.ControlTask {
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

func matchesBundleSearch(bundle models.Bundle, search string) bool {
	if strings.Contains(strings.ToLower(bundle.Version), search) {
		return true
	}
	if strings.Contains(strings.ToLower(bundle.AgentVersion), search) {
		return true
	}
	return false
}

func normalizePolicyLimit(limit int, fallback int) int {
	if limit <= 0 {
		return fallback
	}
	return limit
}

func normalizePolicyOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}
