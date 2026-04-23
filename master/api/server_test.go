package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/apernet/OpenGFW/master/auth"
	"github.com/apernet/OpenGFW/master/bootstrap"
	"github.com/apernet/OpenGFW/master/ingest"
	"github.com/apernet/OpenGFW/master/node"
	"github.com/apernet/OpenGFW/master/policy"
	"github.com/apernet/OpenGFW/master/release"
	reportsvc "github.com/apernet/OpenGFW/master/report"
	masterstate "github.com/apernet/OpenGFW/master/state"
	"github.com/apernet/OpenGFW/pkg/models"
)

type fakeAgentBuilder struct {
	info *models.AgentBuildInfo
}

type testAuthStore struct {
	hasAdmin bool
	nextID   int64
	users    map[string]struct {
		id   int64
		hash string
	}
	sessions map[string]struct {
		userID    int64
		username  string
		expiresAt time.Time
	}
}

func newTestAuthStore() *testAuthStore {
	return &testAuthStore{
		nextID: 1,
		users: make(map[string]struct {
			id   int64
			hash string
		}),
		sessions: make(map[string]struct {
			userID    int64
			username  string
			expiresAt time.Time
		}),
	}
}

func (s *testAuthStore) HasAdminUsers() (bool, error) { return s.hasAdmin, nil }

func (s *testAuthStore) BootstrapAdminUser(username, passwordHash string) (int64, error) {
	if s.hasAdmin {
		return 0, auth.ErrSetupDone
	}
	id := s.nextID
	s.nextID++
	s.users[username] = struct {
		id   int64
		hash string
	}{id: id, hash: passwordHash}
	s.hasAdmin = true
	return id, nil
}

func (s *testAuthStore) GetAdminUserByUsername(username string) (int64, string, string, error) {
	user, ok := s.users[username]
	if !ok {
		return 0, "", "", masterstate.ErrNotFound
	}
	return user.id, username, user.hash, nil
}

func (s *testAuthStore) GetAdminUserByID(id int64) (string, error) {
	for username, user := range s.users {
		if user.id == id {
			return username, nil
		}
	}
	return "", masterstate.ErrNotFound
}

func (s *testAuthStore) UpdateAdminPassword(userID int64, passwordHash string) error {
	for username, user := range s.users {
		if user.id == userID {
			s.users[username] = struct {
				id   int64
				hash string
			}{id: userID, hash: passwordHash}
			return nil
		}
	}
	return masterstate.ErrNotFound
}

func (s *testAuthStore) CreateAdminSession(token string, userID int64, expiresAt time.Time) error {
	username, err := s.GetAdminUserByID(userID)
	if err != nil {
		return err
	}
	s.sessions[token] = struct {
		userID    int64
		username  string
		expiresAt time.Time
	}{userID: userID, username: username, expiresAt: expiresAt}
	return nil
}

func (s *testAuthStore) GetAdminSession(token string) (int64, string, time.Time, error) {
	session, ok := s.sessions[token]
	if !ok {
		return 0, "", time.Time{}, masterstate.ErrNotFound
	}
	return session.userID, session.username, session.expiresAt, nil
}

func (s *testAuthStore) DeleteAdminSession(token string) error {
	delete(s.sessions, token)
	return nil
}

func (b fakeAgentBuilder) EnsureBinary(_ context.Context, _ models.AgentBuildRequest) (*models.AgentBuildInfo, error) {
	return b.info, nil
}

func (b fakeAgentBuilder) EnsureBinaries(_ context.Context, req models.AgentBuildRequest) ([]models.AgentBuildInfo, error) {
	if len(req.Targets) == 0 {
		return []models.AgentBuildInfo{*b.info}, nil
	}
	builds := make([]models.AgentBuildInfo, 0, len(req.Targets))
	for _, target := range req.Targets {
		info := *b.info
		if target.GOOS != "" {
			info.GOOS = target.GOOS
		}
		if target.GOARCH != "" {
			info.GOARCH = target.GOARCH
		}
		builds = append(builds, info)
	}
	return builds, nil
}

func decodeJSONResponse(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
}

func TestReportEventsEndpoint(t *testing.T) {
	nodeSvc := node.NewService()
	_, err := nodeSvc.Register(models.RegistrationRequest{AgentID: "agent-1", Name: "edge-1"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	ingestSvc := ingest.NewService(100, 100)
	ingestSvc.IngestEvents(models.EventBatch{
		AgentID: "agent-1",
		Events: []models.TrafficEvent{
			{Type: "rule_hit", RuleName: "block-ads", Time: time.Now().UTC()},
		},
	})
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/events?agentId=agent-1", nil)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rec.Code)
	}

	var result models.EventQueryResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Total != 1 || len(result.Events) != 1 {
		t.Fatalf("unexpected event query result: %+v", result)
	}
}

func TestReportEventsEndpointSupportsDetailedFilters(t *testing.T) {
	nodeSvc := node.NewService()
	if _, err := nodeSvc.Register(models.RegistrationRequest{AgentID: "agent-1", Name: "edge-1"}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	ingestSvc := ingest.NewService(100, 100)
	ingestSvc.IngestEvents(models.EventBatch{
		AgentID: "agent-1",
		Events: []models.TrafficEvent{
			{
				Type:    "stream_action",
				Proto:   "tcp",
				Action:  "allow",
				SrcIP:   "10.0.0.1",
				DstIP:   "1.1.1.1",
				SrcPort: 34567,
				DstPort: 443,
				Time:    time.Now().UTC(),
			},
		},
	})
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/events?action=allow&srcIp=10.0.0.1&dstIp=1.1.1.1&port=443", nil)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d body=%s", rec.Code, rec.Body.String())
	}

	var result models.EventQueryResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Total != 1 || len(result.Events) != 1 {
		t.Fatalf("unexpected filtered event query result: %+v", result)
	}
}

func TestReportEventsEndpointSupportsSearch(t *testing.T) {
	nodeSvc := node.NewService()
	if _, err := nodeSvc.Register(models.RegistrationRequest{AgentID: "agent-1", Name: "edge-1"}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	ingestSvc := ingest.NewService(100, 100)
	ingestSvc.IngestEvents(models.EventBatch{
		AgentID: "agent-1",
		Events: []models.TrafficEvent{
			{
				Type:     "stream_action",
				Proto:    "tcp",
				Action:   "allow",
				EventID:  "evt-search-1",
				StreamID: 1001,
				SrcIP:    "10.0.0.1",
				DstIP:    "1.1.1.1",
				RuleName: "match-sni",
				Props: map[string]any{
					"tls": map[string]any{
						"req": map[string]any{"sni": "api.github.com"},
					},
				},
				Time: time.Now().UTC(),
			},
		},
	})
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/events?search=github", nil)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d body=%s", rec.Code, rec.Body.String())
	}

	var result models.EventQueryResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Total != 1 || len(result.Events) != 1 {
		t.Fatalf("unexpected search event query result: %+v", result)
	}
}

func TestReportRulesEndpoint(t *testing.T) {
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(100, 100)
	ingestSvc.IngestEvents(models.EventBatch{
		AgentID: "agent-1",
		Events: []models.TrafficEvent{
			{Type: "rule_hit", RuleName: "block-ads", Time: time.Now().UTC()},
		},
	})
	ingestSvc.IngestEvents(models.EventBatch{
		AgentID: "agent-2",
		Events: []models.TrafficEvent{
			{Type: "rule_hit", RuleName: "block-ads", Time: time.Now().UTC().Add(time.Second)},
		},
	})
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/rules", nil)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rec.Code)
	}

	var result []models.RuleReportItem
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(result) != 1 || result[0].Hits != 2 {
		t.Fatalf("unexpected rules response: %+v", result)
	}
}

func TestReportBreakdownEndpoint(t *testing.T) {
	nodeSvc := node.NewService()
	if _, err := nodeSvc.Register(models.RegistrationRequest{AgentID: "agent-1", Name: "edge-1"}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	ingestSvc := ingest.NewService(100, 100)
	ingestSvc.IngestEvents(models.EventBatch{
		AgentID: "agent-1",
		Events: []models.TrafficEvent{
			{
				Type:  "rule_hit",
				Proto: "tcp",
				SrcIP: "10.0.0.1",
				DstIP: "1.1.1.1",
				Time:  time.Now().UTC(),
				Props: map[string]any{
					"tls": map[string]any{
						"req": map[string]any{"sni": "api.example.com"},
					},
				},
			},
			{
				Type:  "stream_action",
				Proto: "udp",
				SrcIP: "10.0.0.1",
				DstIP: "8.8.8.8",
				Time:  time.Now().UTC().Add(time.Second),
			},
		},
	})
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/breakdown?agentId=agent-1&limit=5", nil)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d body=%s", rec.Code, rec.Body.String())
	}

	var result models.EventBreakdown
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(result.SourceIPs) != 1 || result.SourceIPs[0].Value != "10.0.0.1" || result.SourceIPs[0].Events != 2 {
		t.Fatalf("unexpected source ip breakdown: %+v", result.SourceIPs)
	}
	if len(result.DestinationIPs) != 2 {
		t.Fatalf("unexpected destination ip breakdown: %+v", result.DestinationIPs)
	}
	if len(result.SNIs) != 1 || result.SNIs[0].Value != "api.example.com" {
		t.Fatalf("unexpected sni breakdown: %+v", result.SNIs)
	}
	if len(result.Protocols) != 2 {
		t.Fatalf("unexpected protocol breakdown: %+v", result.Protocols)
	}
}

func TestReportMetricsEndpointSupportsAgentFilter(t *testing.T) {
	nodeSvc := node.NewService()
	if _, err := nodeSvc.Register(models.RegistrationRequest{AgentID: "agent-1", Name: "edge-1"}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if _, err := nodeSvc.Register(models.RegistrationRequest{AgentID: "agent-2", Name: "edge-2"}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	ingestSvc := ingest.NewService(100, 100)
	ingestSvc.IngestMetrics(models.MetricBatch{
		AgentID: "agent-1",
		Metrics: []models.MetricSample{
			{Name: "streams_total", Value: 3, Time: time.Now().UTC()},
		},
	})
	ingestSvc.IngestMetrics(models.MetricBatch{
		AgentID: "agent-2",
		Metrics: []models.MetricSample{
			{Name: "streams_total", Value: 5, Time: time.Now().UTC().Add(time.Second)},
		},
	})
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/metrics?agentId=agent-1", nil)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d body=%s", rec.Code, rec.Body.String())
	}

	var result models.MetricQueryResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Total != 1 || len(result.Metrics) != 1 || result.Metrics[0].AgentID != "agent-1" {
		t.Fatalf("unexpected metrics response: %+v", result)
	}
}

func TestNodesEndpointSupportsQueryAndDetail(t *testing.T) {
	nodeSvc := node.NewService()
	_, err := nodeSvc.Register(models.RegistrationRequest{
		AgentID:      "agent-1",
		Name:         "edge-1",
		Hostname:     "edge-1-host",
		ManagementIP: "10.0.0.10",
		Labels:       []string{"edge"},
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	_, err = nodeSvc.Register(models.RegistrationRequest{
		AgentID: "agent-2",
		Name:    "core-1",
		Labels:  []string{"core"},
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingest.NewService(10, 10), reportsvc.NewService(nodeSvc, ingest.NewService(10, 10)), nil, nil)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/nodes?label=edge", nil)
	listRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("unexpected list status: %d", listRec.Code)
	}
	var list models.NodeListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("failed to decode node list: %v", err)
	}
	if list.Total != 1 || len(list.Nodes) != 1 || list.Nodes[0].ID != "agent-1" {
		t.Fatalf("unexpected node list response: %+v", list)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/agent-1", nil)
	detailRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("unexpected detail status: %d", detailRec.Code)
	}
	var detail models.AgentNode
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("failed to decode node detail: %v", err)
	}
	if detail.ID != "agent-1" {
		t.Fatalf("unexpected node detail: %+v", detail)
	}
}

func TestBundleDetailAndTaskDetailEndpoints(t *testing.T) {
	nodeSvc := node.NewService()
	policySvc := policy.NewService()
	releaseSvc := release.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policySvc, releaseSvc, ingestSvc, reportSvc, nil, nil)

	if err := policySvc.AddBundle(models.Bundle{Version: "bundle-v1", Rules: []models.RuleSpec{{Name: "allow-all", Action: "allow", Expr: "true"}}}); err != nil {
		t.Fatalf("failed to add bundle: %v", err)
	}
	tasks, err := policySvc.AssignBundle("bundle-v1", []string{"agent-1"})
	if err != nil {
		t.Fatalf("failed to assign bundle: %v", err)
	}

	bundleReq := httptest.NewRequest(http.MethodGet, "/api/v1/policies/bundles/bundle-v1", nil)
	bundleRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(bundleRec, bundleReq)
	if bundleRec.Code != http.StatusOK {
		t.Fatalf("unexpected bundle detail status: %d", bundleRec.Code)
	}
	var bundle models.Bundle
	if err := json.Unmarshal(bundleRec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("failed to decode bundle detail: %v", err)
	}
	if bundle.Version != "bundle-v1" {
		t.Fatalf("unexpected bundle detail: %+v", bundle)
	}

	taskReq := httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-1/tasks/"+tasks[0].ID+"?status=all", nil)
	taskRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(taskRec, taskReq)
	if taskRec.Code != http.StatusOK {
		t.Fatalf("unexpected task detail status: %d", taskRec.Code)
	}
	var task models.ControlTask
	if err := json.Unmarshal(taskRec.Body.Bytes(), &task); err != nil {
		t.Fatalf("failed to decode task detail: %v", err)
	}
	if task.ID != tasks[0].ID {
		t.Fatalf("unexpected task detail: %+v", task)
	}
}

func TestBuildAgentEndpoint(t *testing.T) {
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	installer := bootstrap.NewSSHInstaller(fakeAgentBuilder{
		info: &models.AgentBuildInfo{
			BinaryName: "opengfw-agent",
			BinaryPath: "/tmp/opengfw-agent",
			GOOS:       "linux",
			GOARCH:     "amd64",
			Checksum:   "sha256:test",
			Rebuilt:    true,
		},
	})
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, installer, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/build/agent", strings.NewReader(`{"goos":"linux","goarch":"amd64","force":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected build status: %d", rec.Code)
	}

	var result models.AgentBuildResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode build response: %v", err)
	}
	if len(result.Builds) != 1 {
		t.Fatalf("expected one build result, got %+v", result)
	}
	if result.Builds[0].BinaryPath != "/tmp/opengfw-agent" || result.Builds[0].GOOS != "linux" || result.Builds[0].GOARCH != "amd64" {
		t.Fatalf("unexpected build response: %+v", result)
	}
}

func TestBuildAgentEndpointSupportsMultipleTargets(t *testing.T) {
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	installer := bootstrap.NewSSHInstaller(fakeAgentBuilder{
		info: &models.AgentBuildInfo{
			BinaryName: "opengfw-agent",
			BinaryPath: "/tmp/opengfw-agent",
			GOOS:       "linux",
			GOARCH:     "amd64",
			Checksum:   "sha256:test",
			Rebuilt:    true,
		},
	})
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, installer, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/build/agent", strings.NewReader(`{"targets":[{"goos":"linux","goarch":"amd64"},{"goos":"darwin","goarch":"arm64"}],"force":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected build status: %d", rec.Code)
	}

	var result models.AgentBuildResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode build response: %v", err)
	}
	if len(result.Builds) != 2 {
		t.Fatalf("expected two build results, got %+v", result)
	}
	if result.Builds[1].GOOS != "darwin" || result.Builds[1].GOARCH != "arm64" {
		t.Fatalf("unexpected batch build response: %+v", result)
	}
}

func TestBootstrapInstallReturnsCommand(t *testing.T) {
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	installer := bootstrap.NewSSHInstaller(fakeAgentBuilder{
		info: &models.AgentBuildInfo{
			BinaryName: "opengfw-agent",
			BinaryPath: "/tmp/opengfw-agent",
			GOOS:       "linux",
			GOARCH:     "amd64",
			Checksum:   "sha256:test",
		},
	})
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, installer, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/install", strings.NewReader(`{
		"name":"edge-1",
		"hostname":"edge-1-host",
		"managementIp":"10.0.0.10",
		"labels":["edge"],
		"agentVersion":"0.1.0",
		"install":{
			"masterUrl":"https://master.example.com",
			"serviceName":"opengfw-agent",
			"binaryName":"opengfw-agent",
			"useSudo":true
		}
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("unexpected bootstrap install status: %d body=%s", rec.Code, rec.Body.String())
	}

	var result models.BootstrapInstallResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode bootstrap install response: %v", err)
	}
	if result.NodeID == "" || result.BootstrapToken == "" {
		t.Fatalf("expected node id and bootstrap token in response: %+v", result)
	}
	if !strings.Contains(result.InstallScriptURL, "/api/v1/bootstrap/scripts/") {
		t.Fatalf("expected install script url in response: %+v", result)
	}
	if !strings.Contains(result.InstallCommand, "curl -fsSL") {
		t.Fatalf("expected install command in response: %+v", result)
	}
}

func TestCreateNodeEndpointReservesBootstrapToken(t *testing.T) {
	nodeSvc := node.NewService()
	policySvc := policy.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policySvc, release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes", strings.NewReader(`{
		"name":"edge-1",
		"hostname":"edge-1-host",
		"managementIp":"10.0.0.10",
		"labels":["edge","hk"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("unexpected create node status: %d body=%s", rec.Code, rec.Body.String())
	}

	var created models.AgentNode
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode node response: %v", err)
	}
	if created.ID == "" || created.Status != models.AgentStatusPending {
		t.Fatalf("unexpected created node: %+v", created)
	}
	if token, ok := nodeSvc.BootstrapTokenForNode(created.ID); !ok || token == "" {
		t.Fatalf("expected bootstrap token for node %s", created.ID)
	}
	tasks := policySvc.PendingTasks(created.ID)
	if len(tasks) != 1 {
		t.Fatalf("expected 1 default bundle task for node %s, got %+v", created.ID, tasks)
	}
	var payload models.BundleTaskPayload
	if err := json.Unmarshal(tasks[0].Payload, &payload); err != nil {
		t.Fatalf("failed to decode default bundle payload: %v", err)
	}
	if payload.Bundle.Version != policy.DefaultReportingBundleVersion {
		t.Fatalf("expected default reporting bundle %q, got %+v", policy.DefaultReportingBundleVersion, payload.Bundle)
	}
}

func TestNodeCommandsEndpointReturnsInstallAndUninstallCommands(t *testing.T) {
	nodeSvc := node.NewService()
	created, _, err := nodeSvc.ReserveBootstrap(models.BootstrapInstallRequest{Name: "edge-1"})
	if err != nil {
		t.Fatalf("reserve bootstrap failed: %v", err)
	}
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	installer := bootstrap.NewSSHInstaller(fakeAgentBuilder{
		info: &models.AgentBuildInfo{
			BinaryName: "opengfw-agent",
			BinaryPath: "/tmp/opengfw-agent",
			GOOS:       "linux",
			GOARCH:     "amd64",
			Checksum:   "sha256:test",
		},
	})
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, installer, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+created.ID+"/commands", nil)
	req.Host = "master.example.com"
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected node commands status: %d body=%s", rec.Code, rec.Body.String())
	}

	var result models.NodeScriptResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode node script response: %v", err)
	}
	if result.NodeID != created.ID || result.BootstrapToken == "" {
		t.Fatalf("unexpected node script response: %+v", result)
	}
	if !strings.Contains(result.InstallScriptURL, "action=install") {
		t.Fatalf("expected install action in script url: %+v", result)
	}
	if !strings.Contains(result.UninstallScriptURL, "action=uninstall") {
		t.Fatalf("expected uninstall action in script url: %+v", result)
	}
	if !strings.Contains(result.InstallCommand, "curl -fsSL") || !strings.Contains(result.UninstallCommand, "curl -fsSL") {
		t.Fatalf("expected generated commands in response: %+v", result)
	}
}

func TestDeleteNodeEndpointRemovesNode(t *testing.T) {
	nodeSvc := node.NewService()
	created, _, err := nodeSvc.ReserveBootstrap(models.BootstrapInstallRequest{Name: "edge-1"})
	if err != nil {
		t.Fatalf("reserve bootstrap failed: %v", err)
	}
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/nodes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("unexpected delete node status: %d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := nodeSvc.Get(created.ID); ok {
		t.Fatalf("expected node %s to be removed", created.ID)
	}
}

func TestManagedReleaseBuildEndpoint(t *testing.T) {
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	file, err := os.CreateTemp(t.TempDir(), "agent-*")
	if err != nil {
		t.Fatalf("create temp binary: %v", err)
	}
	if _, err := file.WriteString("agent-binary"); err != nil {
		t.Fatalf("write temp binary: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temp binary: %v", err)
	}
	installer := bootstrap.NewSSHInstaller(fakeAgentBuilder{
		info: &models.AgentBuildInfo{
			BinaryName: "opengfw-agent",
			BinaryPath: file.Name(),
			GOOS:       "linux",
			GOARCH:     "amd64",
			Checksum:   "sha256:test",
		},
	})
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, installer, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/releases/managed", strings.NewReader(`{
		"version":"agent-v1.2.3",
		"notes":"managed release",
		"targets":[{"goos":"linux","goarch":"amd64"},{"goos":"linux","goarch":"arm64"}]
	}`))
	req.Host = "master.example.com"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("unexpected managed release status: %d body=%s", rec.Code, rec.Body.String())
	}

	var artifact models.ReleaseArtifact
	if err := json.Unmarshal(rec.Body.Bytes(), &artifact); err != nil {
		t.Fatalf("decode managed release response: %v", err)
	}
	if artifact.Version != "agent-v1.2.3" || len(artifact.Assets) != 2 {
		t.Fatalf("unexpected managed release artifact: %+v", artifact)
	}
	if !strings.Contains(artifact.Assets[0].DownloadURL, "/api/v1/releases/assets/agent-v1.2.3/") {
		t.Fatalf("unexpected asset URL: %+v", artifact)
	}
}

func TestReleaseAssetDownloadEndpoint(t *testing.T) {
	nodeSvc := node.NewService()
	releaseSvc := release.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	file, err := os.CreateTemp(t.TempDir(), "agent-*")
	if err != nil {
		t.Fatalf("create temp binary: %v", err)
	}
	if _, err := file.WriteString("agent-binary"); err != nil {
		t.Fatalf("write temp binary: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temp binary: %v", err)
	}
	if err := releaseSvc.AddArtifact(models.ReleaseArtifact{
		Version: "agent-v1.2.3",
		Assets: []models.ReleaseAsset{{
			GOOS:        "linux",
			GOARCH:      "amd64",
			BinaryName:  "opengfw-agent",
			BinaryPath:  file.Name(),
			DownloadURL: "http://master.example.com/api/v1/releases/assets/agent-v1.2.3/linux/amd64",
			Checksum:    "sha256:test",
		}},
	}); err != nil {
		t.Fatalf("add release artifact: %v", err)
	}
	server := NewServer(nil, nodeSvc, policy.NewService(), releaseSvc, ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/releases/assets/agent-v1.2.3/linux/amd64", nil)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected release asset download status: %d body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body != "agent-binary" {
		t.Fatalf("unexpected release asset body: %q", body)
	}
}

func TestEventIngestBackfillsAgentIDFromBatch(t *testing.T) {
	nodeSvc := node.NewService()
	if _, err := nodeSvc.Register(models.RegistrationRequest{AgentID: "agent-1", Name: "edge-1"}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", strings.NewReader(`{
		"agentId":"agent-1",
		"events":[{"type":"rule_hit","ruleName":"block-ads"}]
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("unexpected ingest status: %d body=%s", rec.Code, rec.Body.String())
	}

	events := reportSvc.Events(models.EventQuery{AgentID: "agent-1"})
	if events.Total != 1 || len(events.Events) != 1 {
		t.Fatalf("expected one ingested event, got %+v", events)
	}
	if events.Events[0].AgentID != "agent-1" {
		t.Fatalf("expected event to retain agent id, got %+v", events.Events[0])
	}
	if events.Events[0].Time.IsZero() {
		t.Fatalf("expected ingested event time to be populated, got %+v", events.Events[0])
	}
}

func TestMetricIngestRejectsUnknownNode(t *testing.T) {
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/metrics", strings.NewReader(`{
		"agentId":"agent-missing",
		"metrics":[{"name":"streams_total","value":1}]
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown node, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRootServesFrontend(t *testing.T) {
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected root status: %d", rec.Code)
	}
	if got := rec.Body.String(); got == "" || !contains(got, "OpenGFW 运维主控台") || !contains(got, "/app.js") {
		t.Fatalf("unexpected root body: %q", got)
	}
}

func TestStaticAssetsServeAppAndStyles(t *testing.T) {
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, nil)

	appReq := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	appRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(appRec, appReq)
	if appRec.Code != http.StatusOK {
		t.Fatalf("unexpected app.js status: %d", appRec.Code)
	}
	if got := appRec.Body.String(); got == "" || !contains(got, "submitLogin") || !contains(got, "/api/v1/auth/status") {
		t.Fatalf("unexpected app.js body: %q", got)
	}

	cssReq := httptest.NewRequest(http.MethodGet, "/styles.css", nil)
	cssRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(cssRec, cssReq)
	if cssRec.Code != http.StatusOK {
		t.Fatalf("unexpected styles.css status: %d", cssRec.Code)
	}
	if got := cssRec.Body.String(); got == "" || !contains(got, ".auth-shell") || !contains(got, ".auth-card") {
		t.Fatalf("unexpected styles.css body: %q", got)
	}
}

func TestAuthSetupLoginLogoutFlow(t *testing.T) {
	store := newTestAuthStore()
	authSvc := auth.NewService(store)
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, authSvc)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	testSrv := httptest.NewServer(server.http.Handler)
	defer testSrv.Close()

	client := &http.Client{Jar: jar}

	statusResp, err := client.Get(testSrv.URL + "/api/v1/auth/status")
	if err != nil {
		t.Fatalf("auth status request failed: %v", err)
	}
	var status models.AuthStatusResponse
	decodeJSONResponse(t, statusResp, &status)
	if !status.SetupRequired || status.Authenticated {
		t.Fatalf("unexpected initial auth status: %+v", status)
	}

	setupReq, err := http.NewRequest(http.MethodPost, testSrv.URL+"/api/v1/auth/setup", bytes.NewBufferString(`{"username":"admin","password":"Password123"}`))
	if err != nil {
		t.Fatalf("build setup request: %v", err)
	}
	setupReq.Header.Set("Content-Type", "application/json")
	setupResp, err := client.Do(setupReq)
	if err != nil {
		t.Fatalf("setup request failed: %v", err)
	}
	if setupResp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected setup status: %d", setupResp.StatusCode)
	}
	decodeJSONResponse(t, setupResp, &status)
	if !status.Authenticated || status.User == nil || status.User.Username != "admin" || status.SessionToken == "" {
		t.Fatalf("unexpected setup response: %+v", status)
	}

	nodesResp, err := client.Get(testSrv.URL + "/api/v1/nodes")
	if err != nil {
		t.Fatalf("nodes request after setup failed: %v", err)
	}
	if nodesResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected nodes status after setup: %d", nodesResp.StatusCode)
	}
	nodesResp.Body.Close()

	logoutReq, err := http.NewRequest(http.MethodPost, testSrv.URL+"/api/v1/auth/logout", nil)
	if err != nil {
		t.Fatalf("build logout request: %v", err)
	}
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout request failed: %v", err)
	}
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected logout status: %d", logoutResp.StatusCode)
	}
	logoutResp.Body.Close()

	unauthorizedResp, err := client.Get(testSrv.URL + "/api/v1/nodes")
	if err != nil {
		t.Fatalf("nodes request after logout failed: %v", err)
	}
	if unauthorizedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", unauthorizedResp.StatusCode)
	}
	unauthorizedResp.Body.Close()

	loginReq, err := http.NewRequest(http.MethodPost, testSrv.URL+"/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"Password123"}`))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected login status: %d", loginResp.StatusCode)
	}
	decodeJSONResponse(t, loginResp, &status)
	if !status.Authenticated || status.User == nil || status.User.Username != "admin" || status.SessionToken == "" {
		t.Fatalf("unexpected login response: %+v", status)
	}

	nodesResp, err = client.Get(testSrv.URL + "/api/v1/nodes")
	if err != nil {
		t.Fatalf("nodes request after login failed: %v", err)
	}
	if nodesResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected nodes status after login: %d", nodesResp.StatusCode)
	}
	nodesResp.Body.Close()
}

func TestAuthLoginReturnsConflictWhenSetupRequired(t *testing.T) {
	store := newTestAuthStore()
	authSvc := auth.NewService(store)
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, authSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"Password123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 before initial setup, got %d body=%s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode login error: %v", err)
	}
	if result["error"] != auth.ErrSetupRequired.Error() {
		t.Fatalf("unexpected login error response: %+v", result)
	}
}

func TestAuthStatusAndAdminEndpointsAcceptSessionHeader(t *testing.T) {
	store := newTestAuthStore()
	authSvc := auth.NewService(store)
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, authSvc)

	setupReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", bytes.NewBufferString(`{"username":"admin","password":"Password123"}`))
	setupReq.Header.Set("Content-Type", "application/json")
	setupRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusCreated {
		t.Fatalf("unexpected setup status: %d body=%s", setupRec.Code, setupRec.Body.String())
	}

	var status models.AuthStatusResponse
	if err := json.Unmarshal(setupRec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to decode setup response: %v", err)
	}
	if status.SessionToken == "" {
		t.Fatalf("expected session token in setup response: %+v", status)
	}
	sessionToken := status.SessionToken

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/status", nil)
	statusReq.Header.Set("X-OpenGFW-Session", sessionToken)
	statusRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("unexpected auth status code: %d", statusRec.Code)
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to decode auth status response: %v", err)
	}
	if !status.Authenticated || status.User == nil || status.User.Username != "admin" {
		t.Fatalf("unexpected auth status via header: %+v", status)
	}

	nodesReq := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
	nodesReq.Header.Set("X-OpenGFW-Session", sessionToken)
	nodesRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(nodesRec, nodesReq)
	if nodesRec.Code != http.StatusOK {
		t.Fatalf("unexpected nodes status via session header: %d body=%s", nodesRec.Code, nodesRec.Body.String())
	}
}

func TestAdminPasswordEndpointRejectsWrongCurrentPassword(t *testing.T) {
	store := newTestAuthStore()
	authSvc := auth.NewService(store)
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, authSvc)

	setupReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", bytes.NewBufferString(`{"username":"admin","password":"Password123"}`))
	setupReq.Header.Set("Content-Type", "application/json")
	setupRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusCreated {
		t.Fatalf("unexpected setup status: %d body=%s", setupRec.Code, setupRec.Body.String())
	}

	var status models.AuthStatusResponse
	if err := json.Unmarshal(setupRec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to decode setup response: %v", err)
	}

	changeReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/password", bytes.NewBufferString(`{"currentPassword":"WrongPassword","newPassword":"Password456"}`))
	changeReq.Header.Set("Content-Type", "application/json")
	changeReq.Header.Set("X-OpenGFW-Session", status.SessionToken)
	changeRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(changeRec, changeReq)

	if changeRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong current password, got %d body=%s", changeRec.Code, changeRec.Body.String())
	}

	var result map[string]string
	if err := json.Unmarshal(changeRec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode password change error: %v", err)
	}
	if result["error"] != auth.ErrCurrentPasswordWrong.Error() {
		t.Fatalf("unexpected password change error response: %+v", result)
	}
}

func TestAdminPasswordEndpointUpdatesLoginPassword(t *testing.T) {
	store := newTestAuthStore()
	authSvc := auth.NewService(store)
	nodeSvc := node.NewService()
	ingestSvc := ingest.NewService(10, 10)
	reportSvc := reportsvc.NewService(nodeSvc, ingestSvc)
	server := NewServer(nil, nodeSvc, policy.NewService(), release.NewService(), ingestSvc, reportSvc, nil, authSvc)

	setupReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", bytes.NewBufferString(`{"username":"admin","password":"Password123"}`))
	setupReq.Header.Set("Content-Type", "application/json")
	setupRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusCreated {
		t.Fatalf("unexpected setup status: %d body=%s", setupRec.Code, setupRec.Body.String())
	}

	var status models.AuthStatusResponse
	if err := json.Unmarshal(setupRec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to decode setup response: %v", err)
	}

	changeReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/password", bytes.NewBufferString(`{"currentPassword":"Password123","newPassword":"Password456"}`))
	changeReq.Header.Set("Content-Type", "application/json")
	changeReq.Header.Set("X-OpenGFW-Session", status.SessionToken)
	changeRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(changeRec, changeReq)

	if changeRec.Code != http.StatusNoContent {
		t.Fatalf("unexpected password change status: %d body=%s", changeRec.Code, changeRec.Body.String())
	}

	oldLoginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"Password123"}`))
	oldLoginReq.Header.Set("Content-Type", "application/json")
	oldLoginRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(oldLoginRec, oldLoginReq)
	if oldLoginRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected old password login to fail, got %d body=%s", oldLoginRec.Code, oldLoginRec.Body.String())
	}

	newLoginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"Password456"}`))
	newLoginReq.Header.Set("Content-Type", "application/json")
	newLoginRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(newLoginRec, newLoginReq)
	if newLoginRec.Code != http.StatusOK {
		t.Fatalf("expected new password login to succeed, got %d body=%s", newLoginRec.Code, newLoginRec.Body.String())
	}
}

func contains(s, part string) bool {
	return strings.Contains(s, part)
}
