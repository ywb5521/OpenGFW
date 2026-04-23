package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/OpenGFW/master/auth"
	"github.com/apernet/OpenGFW/master/bootstrap"
	"github.com/apernet/OpenGFW/master/ingest"
	"github.com/apernet/OpenGFW/master/node"
	"github.com/apernet/OpenGFW/master/policy"
	"github.com/apernet/OpenGFW/master/release"
	reportsvc "github.com/apernet/OpenGFW/master/report"
	"github.com/apernet/OpenGFW/pkg/models"
	"github.com/apernet/OpenGFW/pkg/transport"

	"go.uber.org/zap"
)

type Server struct {
	logger    *zap.Logger
	http      *http.Server
	nodes     *node.Service
	policies  *policy.Service
	releases  *release.Service
	ingest    *ingest.Service
	reports   *reportsvc.Service
	bootstrap *bootstrap.SSHInstaller
	auth      *auth.Service
}

func NewServer(logger *zap.Logger, nodes *node.Service, policies *policy.Service, releases *release.Service, ingest *ingest.Service, reports *reportsvc.Service, bootstrapInstaller *bootstrap.SSHInstaller, authService *auth.Service) *Server {
	if logger == nil {
		logger = zap.NewNop()
	}
	srv := &Server{
		logger:    logger,
		nodes:     nodes,
		policies:  policies,
		releases:  releases,
		ingest:    ingest,
		reports:   reports,
		bootstrap: bootstrapInstaller,
		auth:      authService,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.handleHealth)
	mux.HandleFunc("/api/v1/auth/status", srv.handleAuthStatus)
	mux.HandleFunc("/api/v1/auth/setup", srv.handleAuthSetup)
	mux.HandleFunc("/api/v1/auth/login", srv.handleAuthLogin)
	mux.HandleFunc("/api/v1/auth/logout", srv.handleAuthLogout)
	mux.Handle("/api/v1/admin/password", srv.adminOnly(http.HandlerFunc(srv.handleAdminPassword)))
	mux.HandleFunc("/api/v1/agents/register", srv.handleRegister)
	mux.HandleFunc("/api/v1/agents/heartbeat", srv.handleHeartbeat)
	mux.HandleFunc("/api/v1/agents/", srv.handleAgentTasks)
	mux.HandleFunc("/api/v1/bootstrap/scripts/", srv.handleBootstrapScript)
	mux.HandleFunc("/api/v1/bootstrap/binaries/", srv.handleBootstrapBinary)
	mux.Handle("/api/v1/build/agent", srv.adminOnly(http.HandlerFunc(srv.handleAgentBuild)))
	mux.Handle("/api/v1/bootstrap/install", srv.adminOnly(http.HandlerFunc(srv.handleBootstrapInstall)))
	mux.Handle("/api/v1/nodes", srv.adminOnly(http.HandlerFunc(srv.handleNodes)))
	mux.Handle("/api/v1/nodes/", srv.adminOnly(http.HandlerFunc(srv.handleNodes)))
	mux.Handle("/api/v1/policies/bundles", srv.adminOnly(http.HandlerFunc(srv.handleBundles)))
	mux.Handle("/api/v1/policies/bundles/", srv.adminOnly(http.HandlerFunc(srv.handleBundles)))
	mux.Handle("/api/v1/policies/rollouts", srv.adminOnly(http.HandlerFunc(srv.handleBundleRollouts)))
	mux.Handle("/api/v1/releases/managed", srv.adminOnly(http.HandlerFunc(srv.handleManagedReleaseBuild)))
	mux.HandleFunc("/api/v1/releases/assets/", srv.handleReleaseAssetDownload)
	mux.Handle("/api/v1/releases", srv.adminOnly(http.HandlerFunc(srv.handleReleases)))
	mux.Handle("/api/v1/releases/", srv.adminOnly(http.HandlerFunc(srv.handleReleases)))
	mux.Handle("/api/v1/releases/rollouts", srv.adminOnly(http.HandlerFunc(srv.handleReleaseRollouts)))
	mux.HandleFunc("/api/v1/ingest/events", srv.handleEventIngest)
	mux.HandleFunc("/api/v1/ingest/metrics", srv.handleMetricIngest)
	mux.Handle("/api/v1/reports/events", srv.adminOnly(http.HandlerFunc(srv.handleReportEvents)))
	mux.Handle("/api/v1/reports/suspicious", srv.adminOnly(http.HandlerFunc(srv.handleReportSuspicious)))
	mux.Handle("/api/v1/reports/rules", srv.adminOnly(http.HandlerFunc(srv.handleReportRules)))
	mux.Handle("/api/v1/reports/protocols", srv.adminOnly(http.HandlerFunc(srv.handleReportProtocols)))
	mux.Handle("/api/v1/reports/nodes", srv.adminOnly(http.HandlerFunc(srv.handleReportNodes)))
	mux.Handle("/api/v1/reports/breakdown", srv.adminOnly(http.HandlerFunc(srv.handleReportBreakdown)))
	mux.Handle("/api/v1/reports/metrics", srv.adminOnly(http.HandlerFunc(srv.handleReportMetrics)))
	mux.Handle("/api/v1/reports/series/traffic", srv.adminOnly(http.HandlerFunc(srv.handleReportTrafficSeries)))
	mux.Handle("/api/v1/reports/summary", srv.adminOnly(http.HandlerFunc(srv.handleSummary)))
	mux.Handle("/", uiHandler())
	srv.http = &http.Server{Handler: mux}
	return srv
}

func (s *Server) ListenAndServe(addr string) error {
	s.http.Addr = addr
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) adminOnly(next http.Handler) http.Handler {
	if s.auth == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := s.authenticateRequest(r)
		if err != nil {
			transport.WriteError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type authContextKey struct{}

func (s *Server) authenticateRequest(r *http.Request) (*models.AuthenticatedUser, error) {
	if s.auth == nil {
		return nil, nil
	}
	token := s.sessionTokenFromRequest(r)
	if token == "" {
		return nil, http.ErrNoCookie
	}
	return s.auth.Authenticate(token)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.auth == nil {
		transport.WriteJSON(w, http.StatusOK, models.AuthStatusResponse{Authenticated: true, SetupRequired: false})
		return
	}
	token := s.sessionTokenFromRequest(r)
	status, err := s.auth.Status(token)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	transport.WriteJSON(w, http.StatusOK, status)
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.auth == nil {
		transport.WriteError(w, http.StatusNotImplemented, "auth service not configured")
		return
	}
	var req models.AuthSetupRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, token, err := s.auth.Setup(req.Username, req.Password)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, auth.ErrSetupDone) {
			status = http.StatusConflict
		}
		transport.WriteError(w, status, err.Error())
		return
	}
	s.setSessionCookie(w, token)
	transport.WriteJSON(w, http.StatusCreated, models.AuthStatusResponse{
		Authenticated: true,
		SetupRequired: false,
		User:          user,
		SessionToken:  token,
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.auth == nil {
		transport.WriteError(w, http.StatusNotImplemented, "auth service not configured")
		return
	}
	var req models.AuthLoginRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, token, err := s.auth.Login(req.Username, req.Password)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, auth.ErrUnauthorized) {
			status = http.StatusUnauthorized
		} else if errors.Is(err, auth.ErrSetupRequired) {
			status = http.StatusConflict
		}
		transport.WriteError(w, status, err.Error())
		return
	}
	s.setSessionCookie(w, token)
	transport.WriteJSON(w, http.StatusOK, models.AuthStatusResponse{
		Authenticated: true,
		SetupRequired: false,
		User:          user,
		SessionToken:  token,
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.auth == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if token := s.sessionTokenFromRequest(r); token != "" {
		_ = s.auth.Logout(token)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sessionTokenFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie(auth.SessionCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return cookie.Value
	}
	if value := strings.TrimSpace(r.Header.Get("X-OpenGFW-Session")); value != "" {
		return value
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}
	return ""
}

func (s *Server) handleAdminPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.auth == nil {
		transport.WriteError(w, http.StatusNotImplemented, "auth service not configured")
		return
	}
	user, ok := r.Context().Value(authContextKey{}).(*models.AuthenticatedUser)
	if !ok || user == nil {
		transport.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req models.PasswordChangeRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.auth.ChangePassword(user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, auth.ErrUnauthorized) {
			status = http.StatusUnauthorized
		} else if errors.Is(err, auth.ErrCurrentPasswordWrong) {
			status = http.StatusBadRequest
		}
		transport.WriteError(w, status, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req models.RegistrationRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	node, err := s.nodes.Register(req)
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := models.RegistrationResponse{
		AgentID:      node.ID,
		Status:       node.Status,
		RegisteredAt: node.LastSeenAt,
	}
	transport.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBootstrapInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.bootstrap == nil {
		transport.WriteError(w, http.StatusNotImplemented, "bootstrap installer not configured")
		return
	}
	var req models.BootstrapInstallRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Install.MasterURL) == "" {
		req.Install.MasterURL = requestBaseURL(r)
	}
	node, token, err := s.nodes.ReserveBootstrap(req)
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	scriptURL, err := bootstrap.BuildInstallScriptURL(req.Install.MasterURL, token, req.Install)
	if err != nil {
		s.nodes.RevokeBootstrap(token)
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	installDir := strings.TrimSpace(req.Install.InstallDir)
	if installDir == "" {
		installDir = "/usr/local/bin"
	}
	stateDir := strings.TrimSpace(req.Install.StateDir)
	if stateDir == "" {
		stateDir = "/var/lib/opengfw-agent"
	}
	serviceName := strings.TrimSpace(req.Install.ServiceName)
	if serviceName == "" {
		serviceName = "opengfw-agent"
	}
	binaryName := strings.TrimSpace(req.Install.BinaryName)
	if binaryName == "" {
		binaryName = "opengfw-agent"
	}
	if err := s.assignDefaultReportingBundle(node.ID); err != nil {
		s.nodes.RevokeBootstrap(token)
		transport.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	transport.WriteJSON(w, http.StatusCreated, models.BootstrapInstallResponse{
		NodeID:           node.ID,
		ServiceName:      serviceName,
		BinaryPath:       path.Join(installDir, binaryName),
		StateDir:         stateDir,
		InstallScriptURL: scriptURL,
		InstallCommand:   bootstrap.GenerateInstallCommand(scriptURL, req.Install.UseSudo),
		BootstrapToken:   token,
	})
}

func (s *Server) handleAgentBuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.bootstrap == nil {
		transport.WriteError(w, http.StatusNotImplemented, "bootstrap installer not configured")
		return
	}
	var req models.AgentBuildRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	builds, err := s.bootstrap.BuildAgentBinaries(r.Context(), req)
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	transport.WriteJSON(w, http.StatusOK, models.AgentBuildResponse{Builds: builds})
}

func (s *Server) handleBootstrapScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/api/v1/bootstrap/scripts/")
	token = strings.Trim(token, "/")
	if token == "" {
		transport.WriteError(w, http.StatusNotFound, "bootstrap token not found")
		return
	}
	req, err := s.bootstrapRequestForToken(token, r)
	if err != nil {
		transport.WriteError(w, http.StatusNotFound, err.Error())
		return
	}
	script, err := bootstrap.RenderScript(req, token, r.URL.Query().Get("action"))
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

func (s *Server) handleBootstrapBinary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.bootstrap == nil {
		transport.WriteError(w, http.StatusNotImplemented, "bootstrap installer not configured")
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/api/v1/bootstrap/binaries/")
	token = strings.Trim(token, "/")
	if token == "" {
		transport.WriteError(w, http.StatusNotFound, "bootstrap token not found")
		return
	}
	if _, ok := s.nodes.LookupBootstrapToken(token); !ok {
		transport.WriteError(w, http.StatusNotFound, "bootstrap token not found")
		return
	}
	info, err := s.bootstrap.BuildAgentBinary(r.Context(), models.AgentBuildRequest{
		GOOS:   r.URL.Query().Get("goos"),
		GOARCH: r.URL.Query().Get("goarch"),
	})
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", info.BinaryName))
	http.ServeFile(w, r, info.BinaryPath)
}

func (s *Server) bootstrapRequestForToken(token string, r *http.Request) (models.BootstrapInstallRequest, error) {
	nodeInfo, ok := s.nodes.LookupBootstrapToken(token)
	if !ok {
		return models.BootstrapInstallRequest{}, fmt.Errorf("bootstrap token not found")
	}
	req := models.BootstrapInstallRequest{
		Name:         nodeInfo.Name,
		Hostname:     nodeInfo.Hostname,
		ManagementIP: nodeInfo.ManagementIP,
		Labels:       append([]string(nil), nodeInfo.Labels...),
		Metadata:     cloneMap(nodeInfo.Metadata),
		AgentVersion: nodeInfo.AgentVersion,
		Install: models.InstallConfig{
			MasterURL:    firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("masterUrl")), requestBaseURL(r)),
			InstallDir:   r.URL.Query().Get("installDir"),
			StateDir:     r.URL.Query().Get("stateDir"),
			ServiceName:  r.URL.Query().Get("serviceName"),
			BinaryName:   r.URL.Query().Get("binaryName"),
			TargetGOOS:   r.URL.Query().Get("goos"),
			TargetGOARCH: r.URL.Query().Get("goarch"),
		},
	}
	return req, nil
}

func cloneMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.Split(forwarded, ",")[0]
	} else if r.TLS != nil {
		scheme = "https"
	}

	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req models.HeartbeatRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	node, err := s.nodes.Heartbeat(req)
	if err != nil {
		transport.WriteError(w, http.StatusNotFound, err.Error())
		return
	}
	transport.WriteJSON(w, http.StatusOK, models.HeartbeatResponse{
		Status:     node.Status,
		ServerTime: time.Now().UTC(),
	})
}

func (s *Server) handleAgentTasks(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 2 && segments[1] == "tasks" && r.Method == http.MethodGet {
		taskQuery := models.TaskQuery{
			Status: r.URL.Query().Get("status"),
			Type:   models.TaskType(r.URL.Query().Get("type")),
		}
		if taskQuery.Status == "" {
			taskQuery.Status = string(models.TaskStatusPending)
		}
		policyTasks := s.policies.Tasks(segments[0], taskQuery)
		releaseTasks := s.releases.Tasks(segments[0], taskQuery)
		tasks := append([]models.ControlTask(nil), policyTasks.Tasks...)
		tasks = append(tasks, releaseTasks.Tasks...)
		sort.Slice(tasks, func(i, j int) bool {
			return tasks[i].CreatedAt.Before(tasks[j].CreatedAt)
		})
		total := policyTasks.Total + releaseTasks.Total
		offset := parseIntQuery(r, "offset")
		if offset > 0 {
			if offset >= len(tasks) {
				tasks = nil
			} else {
				tasks = tasks[offset:]
			}
		}
		limit := parseIntQuery(r, "limit")
		if limit > 0 && len(tasks) > limit {
			tasks = tasks[:limit]
		}
		transport.WriteJSON(w, http.StatusOK, models.TaskListResponse{Total: total, Tasks: tasks})
		return
	}
	if len(segments) == 3 && segments[1] == "tasks" && r.Method == http.MethodGet {
		if task, ok := s.policies.GetTask(segments[0], segments[2]); ok {
			transport.WriteJSON(w, http.StatusOK, task)
			return
		}
		if task, ok := s.releases.GetTask(segments[0], segments[2]); ok {
			transport.WriteJSON(w, http.StatusOK, task)
			return
		}
		transport.WriteError(w, http.StatusNotFound, "task not found")
		return
	}
	if len(segments) == 4 && segments[1] == "tasks" && segments[3] == "ack" && r.Method == http.MethodPost {
		var req models.AckTaskRequest
		if err := transport.ReadJSON(r, &req); err != nil {
			transport.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if s.policies.AckTask(segments[0], segments[2], req) || s.releases.AckTask(segments[0], segments[2], req) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		transport.WriteError(w, http.StatusNotFound, "task not found")
		return
	}
	transport.WriteError(w, http.StatusNotFound, "endpoint not found")
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Path != "/api/v1/nodes" {
			if strings.HasSuffix(r.URL.Path, "/commands") {
				transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
			if id == "" {
				transport.WriteError(w, http.StatusNotFound, "node not found")
				return
			}
			node, ok := s.nodes.Get(id)
			if !ok {
				transport.WriteError(w, http.StatusNotFound, "node not found")
				return
			}
			transport.WriteJSON(w, http.StatusOK, node)
			return
		}
		query := models.NodeQuery{
			Status: models.AgentStatus(r.URL.Query().Get("status")),
			Label:  r.URL.Query().Get("label"),
			Search: r.URL.Query().Get("search"),
			Offset: parseIntQuery(r, "offset"),
			Limit:  parseIntQuery(r, "limit"),
		}
		transport.WriteJSON(w, http.StatusOK, s.nodes.Query(query))
	case http.MethodPost:
		if r.URL.Path == "/api/v1/nodes" {
			var req models.BootstrapInstallRequest
			if err := transport.ReadJSON(r, &req); err != nil {
				transport.WriteError(w, http.StatusBadRequest, err.Error())
				return
			}
			node, _, err := s.nodes.ReserveBootstrap(req)
			if err != nil {
				transport.WriteError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := s.assignDefaultReportingBundle(node.ID); err != nil {
				if token, ok := s.nodes.BootstrapTokenForNode(node.ID); ok {
					s.nodes.RevokeBootstrap(token)
				}
				transport.WriteError(w, http.StatusInternalServerError, err.Error())
				return
			}
			transport.WriteJSON(w, http.StatusCreated, node)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/commands") {
			if s.bootstrap == nil {
				transport.WriteError(w, http.StatusNotImplemented, "bootstrap installer not configured")
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"), "/commands")
			id = strings.Trim(id, "/")
			if id == "" {
				transport.WriteError(w, http.StatusNotFound, "node not found")
				return
			}
			node, ok := s.nodes.Get(id)
			if !ok {
				transport.WriteError(w, http.StatusNotFound, "node not found")
				return
			}
			token, err := s.nodes.EnsureBootstrapToken(id)
			if err != nil {
				transport.WriteError(w, http.StatusBadRequest, err.Error())
				return
			}
			installConfig := models.InstallConfig{
				MasterURL: firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("masterUrl")), requestBaseURL(r)),
				ServiceName: firstNonEmpty(
					strings.TrimSpace(r.URL.Query().Get("serviceName")),
					"opengfw-agent",
				),
				BinaryName: firstNonEmpty(
					strings.TrimSpace(r.URL.Query().Get("binaryName")),
					"opengfw-agent",
				),
				InstallDir: firstNonEmpty(
					strings.TrimSpace(r.URL.Query().Get("installDir")),
					"/usr/local/bin",
				),
				StateDir: firstNonEmpty(
					strings.TrimSpace(r.URL.Query().Get("stateDir")),
					"/var/lib/opengfw-agent",
				),
				UseSudo: true,
			}
			if values, ok := r.URL.Query()["useSudo"]; ok && len(values) > 0 {
				installConfig.UseSudo = values[0] != "false"
			}
			installScriptURL, err := bootstrap.BuildInstallScriptURL(installConfig.MasterURL, token, installConfig)
			if err != nil {
				transport.WriteError(w, http.StatusBadRequest, err.Error())
				return
			}
			uninstallScriptURL, err := bootstrap.BuildUninstallScriptURL(installConfig.MasterURL, token, installConfig)
			if err != nil {
				transport.WriteError(w, http.StatusBadRequest, err.Error())
				return
			}
			transport.WriteJSON(w, http.StatusOK, models.NodeScriptResponse{
				NodeID:             node.ID,
				ServiceName:        installConfig.ServiceName,
				BinaryPath:         path.Join(installConfig.InstallDir, installConfig.BinaryName),
				StateDir:           installConfig.StateDir,
				BootstrapToken:     token,
				InstallScriptURL:   installScriptURL,
				InstallCommand:     bootstrap.GenerateInstallCommand(installScriptURL, installConfig.UseSudo),
				UninstallScriptURL: uninstallScriptURL,
				UninstallCommand:   bootstrap.GenerateUninstallCommand(uninstallScriptURL, installConfig.UseSudo),
			})
			return
		}
		transport.WriteError(w, http.StatusNotFound, "node not found")
	case http.MethodDelete:
		if r.URL.Path == "/api/v1/nodes" || strings.HasSuffix(r.URL.Path, "/commands") {
			transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
		id = strings.Trim(id, "/")
		if id == "" {
			transport.WriteError(w, http.StatusNotFound, "node not found")
			return
		}
		if err := s.nodes.Delete(id); err != nil {
			transport.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleBundles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Path != "/api/v1/policies/bundles" {
			version := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/bundles/")
			if version == "" {
				transport.WriteError(w, http.StatusNotFound, "bundle not found")
				return
			}
			bundle, ok := s.policies.GetBundle(version)
			if !ok {
				transport.WriteError(w, http.StatusNotFound, "bundle not found")
				return
			}
			transport.WriteJSON(w, http.StatusOK, bundle)
			return
		}
		transport.WriteJSON(w, http.StatusOK, s.policies.QueryBundles(models.BundleQuery{
			Version: r.URL.Query().Get("version"),
			Search:  r.URL.Query().Get("search"),
			Offset:  parseIntQuery(r, "offset"),
			Limit:   parseIntQuery(r, "limit"),
		}))
	case http.MethodPost:
		var bundle models.Bundle
		if err := transport.ReadJSON(r, &bundle); err != nil {
			transport.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.policies.AddBundle(bundle); err != nil {
			transport.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		transport.WriteJSON(w, http.StatusCreated, bundle)
	default:
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) assignDefaultReportingBundle(agentID string) error {
	if s.policies == nil || strings.TrimSpace(agentID) == "" {
		return nil
	}
	_, err := s.policies.AssignBundle(policy.DefaultReportingBundleVersion, []string{agentID})
	return err
}

func (s *Server) handleBundleRollouts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req models.BundleRolloutRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	tasks, err := s.policies.AssignBundle(req.BundleVersion, req.AgentIDs)
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	transport.WriteJSON(w, http.StatusAccepted, models.TaskListResponse{Tasks: tasks})
}

func (s *Server) handleReleases(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Path != "/api/v1/releases" {
			version := strings.TrimPrefix(r.URL.Path, "/api/v1/releases/")
			if version == "" {
				transport.WriteError(w, http.StatusNotFound, "release not found")
				return
			}
			artifact, ok := s.releases.GetArtifact(version)
			if !ok {
				transport.WriteError(w, http.StatusNotFound, "release not found")
				return
			}
			transport.WriteJSON(w, http.StatusOK, artifact)
			return
		}
		transport.WriteJSON(w, http.StatusOK, s.releases.QueryArtifacts(models.ReleaseQuery{
			Version: r.URL.Query().Get("version"),
			Search:  r.URL.Query().Get("search"),
			Offset:  parseIntQuery(r, "offset"),
			Limit:   parseIntQuery(r, "limit"),
		}))
	case http.MethodPost:
		var artifact models.ReleaseArtifact
		if err := transport.ReadJSON(r, &artifact); err != nil {
			transport.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.releases.AddArtifact(artifact); err != nil {
			transport.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		transport.WriteJSON(w, http.StatusCreated, artifact)
	default:
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleManagedReleaseBuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.bootstrap == nil {
		transport.WriteError(w, http.StatusNotImplemented, "bootstrap installer not configured")
		return
	}
	var req models.ManagedReleaseBuildRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	version := strings.TrimSpace(req.Version)
	if version == "" {
		transport.WriteError(w, http.StatusBadRequest, "release version is required")
		return
	}
	builds, err := s.bootstrap.BuildAgentBinaries(r.Context(), models.AgentBuildRequest{
		Targets: req.Targets,
		Force:   req.Force,
	})
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	baseURL := requestBaseURL(r)
	if baseURL == "" {
		transport.WriteError(w, http.StatusBadRequest, "request host is required")
		return
	}
	assets := make([]models.ReleaseAsset, 0, len(builds))
	for _, build := range builds {
		downloadURL, err := buildReleaseAssetDownloadURL(baseURL, version, build.GOOS, build.GOARCH)
		if err != nil {
			transport.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		assets = append(assets, models.ReleaseAsset{
			GOOS:        build.GOOS,
			GOARCH:      build.GOARCH,
			BinaryName:  build.BinaryName,
			DownloadURL: downloadURL,
			Checksum:    build.Checksum,
			BuiltAt:     build.BuiltAt,
			BinaryPath:  build.BinaryPath,
		})
	}
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].GOOS == assets[j].GOOS {
			return assets[i].GOARCH < assets[j].GOARCH
		}
		return assets[i].GOOS < assets[j].GOOS
	})
	artifact := models.ReleaseArtifact{
		Version:   version,
		Notes:     strings.TrimSpace(req.Notes),
		Assets:    assets,
		CreatedAt: time.Now().UTC(),
	}
	if len(assets) == 1 {
		artifact.DownloadURL = assets[0].DownloadURL
		artifact.Checksum = assets[0].Checksum
	}
	if err := s.releases.AddArtifact(artifact); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	transport.WriteJSON(w, http.StatusCreated, artifact)
}

func (s *Server) handleReleaseAssetDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/releases/assets/"), "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 {
		transport.WriteError(w, http.StatusNotFound, "release asset not found")
		return
	}
	version, goos, goarch := parts[0], parts[1], parts[2]
	artifact, ok := s.releases.GetArtifact(version)
	if !ok {
		transport.WriteError(w, http.StatusNotFound, "release not found")
		return
	}
	asset, ok := findReleaseAsset(artifact, goos, goarch)
	if !ok || strings.TrimSpace(asset.BinaryPath) == "" {
		transport.WriteError(w, http.StatusNotFound, "release asset not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", firstNonEmpty(asset.BinaryName, path.Base(asset.BinaryPath), "opengfw-agent")))
	http.ServeFile(w, r, asset.BinaryPath)
}

func buildReleaseAssetDownloadURL(baseURL, version, goos, goarch string) (string, error) {
	if baseURL == "" {
		return "", fmt.Errorf("base URL is required")
	}
	version = strings.TrimSpace(version)
	goos = strings.TrimSpace(goos)
	goarch = strings.TrimSpace(goarch)
	if version == "" || goos == "" || goarch == "" {
		return "", fmt.Errorf("release version, goos, and goarch are required")
	}
	return strings.TrimRight(baseURL, "/") + "/api/v1/releases/assets/" + url.PathEscape(version) + "/" + url.PathEscape(goos) + "/" + url.PathEscape(goarch), nil
}

func findReleaseAsset(artifact models.ReleaseArtifact, goos, goarch string) (models.ReleaseAsset, bool) {
	for _, asset := range artifact.Assets {
		if asset.GOOS == goos && asset.GOARCH == goarch {
			return asset, true
		}
	}
	return models.ReleaseAsset{}, false
}

func (s *Server) handleReleaseRollouts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req models.ReleaseRolloutRequest
	if err := transport.ReadJSON(r, &req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	tasks, err := s.releases.Assign(req.Version, req.AgentIDs)
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	transport.WriteJSON(w, http.StatusAccepted, models.TaskListResponse{Tasks: tasks})
}

func (s *Server) handleEventIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var batch models.EventBatch
	if err := transport.ReadJSON(r, &batch); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if batch.AgentID == "" {
		transport.WriteError(w, http.StatusBadRequest, "agentId is required")
		return
	}
	if _, ok := s.nodes.Get(batch.AgentID); !ok {
		transport.WriteError(w, http.StatusNotFound, "node not found")
		return
	}
	normalized, err := ingest.PrepareEventBatch(batch)
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	accepted := s.ingest.IngestEvents(normalized)
	transport.WriteJSON(w, http.StatusAccepted, models.AcceptedResponse{Accepted: accepted})
}

func (s *Server) handleMetricIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var batch models.MetricBatch
	if err := transport.ReadJSON(r, &batch); err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if batch.AgentID == "" {
		transport.WriteError(w, http.StatusBadRequest, "agentId is required")
		return
	}
	if _, ok := s.nodes.Get(batch.AgentID); !ok {
		transport.WriteError(w, http.StatusNotFound, "node not found")
		return
	}
	normalized, err := ingest.PrepareMetricBatch(batch)
	if err != nil {
		transport.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	accepted := s.ingest.IngestMetrics(normalized)
	transport.WriteJSON(w, http.StatusAccepted, models.AcceptedResponse{Accepted: accepted})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	transport.WriteJSON(w, http.StatusOK, s.reports.Summary())
}

func (s *Server) handleReportEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	query := models.EventQuery{
		AgentID:      r.URL.Query().Get("agentId"),
		Search:       r.URL.Query().Get("search"),
		Type:         r.URL.Query().Get("type"),
		Proto:        r.URL.Query().Get("proto"),
		RuleName:     r.URL.Query().Get("ruleName"),
		Action:       r.URL.Query().Get("action"),
		SrcIP:        r.URL.Query().Get("srcIp"),
		DstIP:        r.URL.Query().Get("dstIp"),
		Port:         parseIntQuery(r, "port"),
		MinSuspicion: parseIntQuery(r, "minSuspicion"),
		Offset:       parseIntQuery(r, "offset"),
		Limit:        parseIntQuery(r, "limit"),
		Since:        parseTimeQuery(r, "since"),
		Until:        parseTimeQuery(r, "until"),
	}
	transport.WriteJSON(w, http.StatusOK, s.reports.Events(query))
}

func (s *Server) handleReportSuspicious(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	transport.WriteJSON(w, http.StatusOK, s.reports.SuspiciousEvents(parseIntQuery(r, "limit")))
}

func (s *Server) handleReportRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	transport.WriteJSON(w, http.StatusOK, s.reports.Rules(models.TimeRangeQuery{
		Since: parseTimeQuery(r, "since"),
		Until: parseTimeQuery(r, "until"),
		Limit: parseIntQuery(r, "limit"),
	}))
}

func (s *Server) handleReportProtocols(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	transport.WriteJSON(w, http.StatusOK, s.reports.Protocols(models.TimeRangeQuery{
		Since: parseTimeQuery(r, "since"),
		Until: parseTimeQuery(r, "until"),
	}))
}

func (s *Server) handleReportNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	transport.WriteJSON(w, http.StatusOK, s.reports.Nodes(models.TimeRangeQuery{
		Since: parseTimeQuery(r, "since"),
		Until: parseTimeQuery(r, "until"),
	}))
}

func (s *Server) handleReportBreakdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	transport.WriteJSON(w, http.StatusOK, s.reports.EventBreakdown(models.TimeRangeQuery{
		AgentID: r.URL.Query().Get("agentId"),
		Since:   parseTimeQuery(r, "since"),
		Until:   parseTimeQuery(r, "until"),
		Limit:   parseIntQuery(r, "limit"),
	}))
}

func (s *Server) handleReportMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	transport.WriteJSON(w, http.StatusOK, s.reports.Metrics(models.MetricQuery{
		AgentID: r.URL.Query().Get("agentId"),
		Name:    r.URL.Query().Get("name"),
		Offset:  parseIntQuery(r, "offset"),
		Limit:   parseIntQuery(r, "limit"),
		Since:   parseTimeQuery(r, "since"),
		Until:   parseTimeQuery(r, "until"),
	}))
}

func (s *Server) handleReportTrafficSeries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transport.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	transport.WriteJSON(w, http.StatusOK, s.reports.TrafficSeries(models.TimeRangeQuery{
		AgentID: r.URL.Query().Get("agentId"),
		Since:   parseTimeQuery(r, "since"),
		Until:   parseTimeQuery(r, "until"),
		Limit:   parseIntQuery(r, "limit"),
	}))
}

func parseIntQuery(r *http.Request, key string) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return 0
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}

func parseTimeQuery(r *http.Request, key string) time.Time {
	value := r.URL.Query().Get(key)
	if value == "" {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return ts
}
