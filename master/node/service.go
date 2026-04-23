package node

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	masterstate "github.com/apernet/OpenGFW/master/state"
	"github.com/apernet/OpenGFW/pkg/models"
)

type NodeStore interface {
	UpsertNode(models.AgentNode) error
	DeleteNode(string) error
	ListNodes() ([]models.AgentNode, error)
	SaveBootstrapToken(token, agentID string) error
	ConsumeBootstrapToken(token string) (string, error)
	DeleteBootstrapToken(token string) error
	SaveSequence(name string, value uint64) error
}

type Service struct {
	mu           sync.RWMutex
	nodes        map[string]*models.AgentNode
	bootstrap    map[string]string
	seq          uint64
	nowFunc      func() time.Time
	offlineAfter time.Duration
	persist      func(masterstate.NodeSnapshot) error
	store        NodeStore
}

func NewService() *Service {
	return NewServiceWithSnapshot(masterstate.NodeSnapshot{}, nil)
}

func NewServiceWithSnapshot(snapshot masterstate.NodeSnapshot, persist func(masterstate.NodeSnapshot) error) *Service {
	return NewServiceWithSnapshotAndStore(snapshot, persist, nil)
}

func NewServiceWithSnapshotAndStore(snapshot masterstate.NodeSnapshot, persist func(masterstate.NodeSnapshot) error, store NodeStore) *Service {
	if snapshot.Nodes == nil {
		snapshot.Nodes = make(map[string]*models.AgentNode)
	}
	if snapshot.Bootstrap == nil {
		snapshot.Bootstrap = make(map[string]string)
	}
	return &Service{
		nodes:        snapshot.Nodes,
		bootstrap:    snapshot.Bootstrap,
		seq:          snapshot.Seq,
		nowFunc:      func() time.Time { return time.Now().UTC() },
		offlineAfter: time.Minute,
		persist:      persist,
		store:        store,
	}
}

func (s *Service) Register(req models.RegistrationRequest) (models.AgentNode, error) {
	s.mu.Lock()

	now := s.nowFunc()
	id := req.AgentID
	if id == "" && req.BootstrapToken != "" {
		var ok bool
		id, ok = s.bootstrap[req.BootstrapToken]
		if !ok {
			s.mu.Unlock()
			return models.AgentNode{}, fmt.Errorf("invalid bootstrap token")
		}
	}
	if id == "" {
		s.seq++
		id = fmt.Sprintf("agent-%d", s.seq)
	}
	node, ok := s.nodes[id]
	if !ok {
		node = &models.AgentNode{ID: id}
		s.nodes[id] = node
	}
	node.Name = req.Name
	node.Hostname = req.Hostname
	node.ManagementIP = req.ManagementIP
	node.AgentVersion = req.AgentVersion
	node.Labels = append([]string(nil), req.Labels...)
	node.Capabilities = append([]string(nil), req.Capabilities...)
	node.Metadata = cloneStringMap(req.Metadata)
	node.Status = models.AgentStatusOnline
	node.LastSeenAt = now
	if err := s.syncNodeLocked(*node); err != nil {
		s.mu.Unlock()
		return models.AgentNode{}, err
	}
	s.mu.Unlock()
	return *node, nil
}

func (s *Service) ReserveBootstrap(req models.BootstrapInstallRequest) (models.AgentNode, string, error) {
	s.mu.Lock()

	token := req.Install.BootstrapToken
	if token == "" {
		var err error
		token, err = models.GenerateBootstrapToken()
		if err != nil {
			s.mu.Unlock()
			return models.AgentNode{}, "", err
		}
	}
	if _, exists := s.bootstrap[token]; exists {
		s.mu.Unlock()
		return models.AgentNode{}, "", fmt.Errorf("bootstrap token already exists")
	}

	s.seq++
	id := fmt.Sprintf("agent-%d", s.seq)
	node := &models.AgentNode{
		ID:           id,
		Name:         req.Name,
		Hostname:     req.Hostname,
		ManagementIP: req.ManagementIP,
		Labels:       append([]string(nil), req.Labels...),
		Status:       models.AgentStatusPending,
		AgentVersion: req.AgentVersion,
		LastSeenAt:   s.nowFunc(),
		Metadata:     cloneStringMap(req.Metadata),
	}
	s.nodes[id] = node
	s.bootstrap[token] = id
	if err := s.syncNodeLocked(*node); err != nil {
		s.mu.Unlock()
		return models.AgentNode{}, "", err
	}
	if err := s.syncBootstrapLocked(token, id); err != nil {
		s.mu.Unlock()
		return models.AgentNode{}, "", err
	}
	s.mu.Unlock()
	return *node, token, nil
}

func (s *Service) RevokeBootstrap(token string) {
	s.mu.Lock()

	id, ok := s.bootstrap[token]
	delete(s.bootstrap, token)
	if !ok {
		s.persistLocked()
		s.mu.Unlock()
		return
	}
	if node, exists := s.nodes[id]; exists && node.Status == models.AgentStatusPending {
		delete(s.nodes, id)
	}
	if s.store != nil {
		_ = s.store.DeleteBootstrapToken(token)
		if id != "" {
			_ = s.store.DeleteNode(id)
		}
	} else {
		s.persistLocked()
	}
	s.mu.Unlock()
}

func (s *Service) LookupBootstrapToken(token string) (models.AgentNode, bool) {
	s.mu.RLock()
	agentID, ok := s.bootstrap[token]
	if !ok {
		s.mu.RUnlock()
		return models.AgentNode{}, false
	}
	node, exists := s.nodes[agentID]
	if !exists {
		s.mu.RUnlock()
		return models.AgentNode{}, false
	}
	out := *node
	s.mu.RUnlock()
	return out, true
}

func (s *Service) BootstrapTokenForNode(agentID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for token, id := range s.bootstrap {
		if id == agentID {
			return token, true
		}
	}
	return "", false
}

func (s *Service) EnsureBootstrapToken(agentID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.nodes[agentID]; !ok {
		return "", fmt.Errorf("node not found")
	}
	for token, id := range s.bootstrap {
		if id == agentID {
			return token, nil
		}
	}

	for {
		token, err := models.GenerateBootstrapToken()
		if err != nil {
			return "", err
		}
		if _, exists := s.bootstrap[token]; exists {
			continue
		}
		s.bootstrap[token] = agentID
		if err := s.syncBootstrapLocked(token, agentID); err != nil {
			delete(s.bootstrap, token)
			return "", err
		}
		return token, nil
	}
}

func (s *Service) Delete(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.nodes[agentID]; !ok {
		return fmt.Errorf("node not found")
	}

	tokens := make([]string, 0, 1)
	for token, id := range s.bootstrap {
		if id == agentID {
			tokens = append(tokens, token)
		}
	}

	if s.store != nil {
		if err := s.store.DeleteNode(agentID); err != nil {
			return err
		}
		for _, token := range tokens {
			if err := s.store.DeleteBootstrapToken(token); err != nil {
				return err
			}
		}
	}

	delete(s.nodes, agentID)
	for _, token := range tokens {
		delete(s.bootstrap, token)
	}
	if s.store == nil {
		s.persistLocked()
	}
	return nil
}

func (s *Service) Heartbeat(req models.HeartbeatRequest) (models.AgentNode, error) {
	s.mu.Lock()

	node, ok := s.nodes[req.AgentID]
	if !ok {
		s.mu.Unlock()
		return models.AgentNode{}, fmt.Errorf("agent %q not registered", req.AgentID)
	}
	node.Name = req.Name
	node.Hostname = req.Hostname
	node.AgentVersion = req.AgentVersion
	node.BundleVersion = req.BundleVersion
	node.Capabilities = append([]string(nil), req.Capabilities...)
	node.Metadata = cloneStringMap(req.Metadata)
	node.Status = models.AgentStatusOnline
	node.LastSeenAt = s.nowFunc()
	if err := s.syncNodeLocked(*node); err != nil {
		s.mu.Unlock()
		return models.AgentNode{}, err
	}
	s.mu.Unlock()
	return *node, nil
}

func (s *Service) List() []models.AgentNode {
	nodes := s.listAll()
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	return nodes
}

func (s *Service) Get(id string) (models.AgentNode, bool) {
	for _, node := range s.listAll() {
		if node.ID == id {
			return node, true
		}
	}
	return models.AgentNode{}, false
}

func (s *Service) Query(query models.NodeQuery) models.NodeListResponse {
	nodes := s.listAll()
	filtered := make([]models.AgentNode, 0, len(nodes))
	search := strings.ToLower(strings.TrimSpace(query.Search))
	for _, node := range nodes {
		if query.Status != "" && node.Status != query.Status {
			continue
		}
		if query.Label != "" && !containsString(node.Labels, query.Label) {
			continue
		}
		if search != "" && !matchesNodeSearch(node, search) {
			continue
		}
		filtered = append(filtered, node)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].ID < filtered[j].ID
	})
	total := len(filtered)
	offset := normalizeOffset(query.Offset)
	if offset >= len(filtered) {
		return models.NodeListResponse{Total: total}
	}
	if offset > 0 {
		filtered = filtered[offset:]
	}
	limit := normalizeLimit(query.Limit, 100)
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return models.NodeListResponse{
		Total: total,
		Nodes: filtered,
	}
}

func (s *Service) listAll() []models.AgentNode {
	if s.store != nil {
		if nodes, err := s.store.ListNodes(); err == nil {
			return s.normalizeNodeStatuses(nodes)
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	nodes := make([]models.AgentNode, 0, len(s.nodes))
	for _, node := range s.nodes {
		nodes = append(nodes, *node)
	}
	return s.normalizeNodeStatuses(nodes)
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func (s *Service) snapshotLocked() masterstate.NodeSnapshot {
	return masterstate.NodeSnapshot{
		Nodes:     cloneNodeMap(s.nodes),
		Bootstrap: cloneBootstrapMap(s.bootstrap),
		Seq:       s.seq,
	}
}

func (s *Service) persistLocked() {
	if s.persist == nil {
		return
	}
	_ = s.persist(s.snapshotLocked())
}

func (s *Service) syncNodeLocked(node models.AgentNode) error {
	if s.store != nil {
		if err := s.store.UpsertNode(node); err != nil {
			return err
		}
		return s.store.SaveSequence("nodes", s.seq)
	}
	s.persistLocked()
	return nil
}

func (s *Service) syncBootstrapLocked(token, agentID string) error {
	if s.store != nil {
		if err := s.store.SaveBootstrapToken(token, agentID); err != nil {
			return err
		}
		return s.store.SaveSequence("nodes", s.seq)
	}
	s.persistLocked()
	return nil
}

func cloneNodeMap(src map[string]*models.AgentNode) map[string]*models.AgentNode {
	if len(src) == 0 {
		return make(map[string]*models.AgentNode)
	}
	dst := make(map[string]*models.AgentNode, len(src))
	for key, value := range src {
		if value == nil {
			continue
		}
		cp := *value
		dst[key] = &cp
	}
	return dst
}

func cloneBootstrapMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return make(map[string]string)
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func matchesNodeSearch(node models.AgentNode, search string) bool {
	fields := []string{
		node.ID,
		node.Name,
		node.Hostname,
		node.ManagementIP,
		node.AgentVersion,
		node.BundleVersion,
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}
	return false
}

func normalizeLimit(limit int, fallback int) int {
	if limit <= 0 {
		return fallback
	}
	return limit
}

func normalizeOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func (s *Service) normalizeNodeStatuses(nodes []models.AgentNode) []models.AgentNode {
	if len(nodes) == 0 {
		return nodes
	}
	now := s.nowFunc()
	out := make([]models.AgentNode, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, s.normalizeNodeStatus(now, node))
	}
	return out
}

func (s *Service) normalizeNodeStatus(now time.Time, node models.AgentNode) models.AgentNode {
	if s.offlineAfter <= 0 {
		return node
	}
	if node.Status == models.AgentStatusOnline && !node.LastSeenAt.IsZero() && now.Sub(node.LastSeenAt) > s.offlineAfter {
		node.Status = models.AgentStatusOffline
	}
	return node
}
