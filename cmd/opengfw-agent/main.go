package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"syscall"
	"time"

	"github.com/apernet/OpenGFW/agent"
	agentbundle "github.com/apernet/OpenGFW/agent/bundle"
	"github.com/apernet/OpenGFW/agent/control"
	"github.com/apernet/OpenGFW/agent/report"
	"github.com/apernet/OpenGFW/agent/runtime"
	"github.com/apernet/OpenGFW/agent/state"
	"github.com/apernet/OpenGFW/agent/upgrade"

	"go.uber.org/zap"
)

const defaultAgentVersion = "0.1.0"

func main() {
	masterURL := flag.String("master", "http://127.0.0.1:8080", "master base URL")
	stateDir := flag.String("state-dir", ".opengfw-agent", "agent state directory")
	name := flag.String("name", "", "agent display name")
	hostname := flag.String("hostname", "", "agent hostname")
	managementIP := flag.String("management-ip", "", "agent management IP")
	version := flag.String("version", envOrDefault("OPENGFW_AGENT_VERSION", ""), "agent version")
	bootstrapToken := flag.String("bootstrap-token", envOrDefault("OPENGFW_BOOTSTRAP_TOKEN", ""), "bootstrap token")
	serviceName := flag.String("service-name", envOrDefault("OPENGFW_SERVICE_NAME", "opengfw-agent"), "service name used for self-upgrade")
	binaryPath := flag.String("binary-path", envOrDefault("OPENGFW_BINARY_PATH", ""), "installed binary path used for self-upgrade")
	flag.Parse()

	host := *hostname
	if host == "" {
		if detected, err := os.Hostname(); err == nil {
			host = detected
		}
	}
	displayName := *name
	if displayName == "" {
		displayName = host
	}
	execPath := *binaryPath
	if execPath == "" {
		if detected, err := os.Executable(); err == nil {
			execPath = detected
		}
	}
	agentVersion := resolveAgentVersion(*version, *stateDir)

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := state.NewFileStore(*stateDir)
	if err != nil {
		logger.Fatal("failed to initialize state store", zap.Error(err))
	}
	bundles, err := agentbundle.NewManager(ctx, store)
	if err != nil {
		logger.Fatal("failed to initialize bundle manager", zap.Error(err))
	}

	client := control.NewHTTPClient(*masterURL, &http.Client{Timeout: 10 * time.Second})
	collector := report.NewCollector(0, store)
	upgrader, err := upgrade.NewStager(*stateDir, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		logger.Fatal("failed to initialize upgrade stager", zap.Error(err))
	}
	app := agent.NewApp(
		agent.Config{
			Name:            displayName,
			Hostname:        host,
			ManagementIP:    *managementIP,
			AgentVersion:    agentVersion,
			BootstrapToken:  *bootstrapToken,
			ServiceName:     *serviceName,
			InstalledBinary: execPath,
			Capabilities:    []string{"nfqueue", "rule-runtime", "report-uploader"},
			Metadata: map[string]string{
				"goos":   goruntime.GOOS,
				"goarch": goruntime.GOARCH,
			},
			HeartbeatInterval: 15 * time.Second,
			FlushInterval:     10 * time.Second,
			EventBatchSize:    256,
			MetricBatchSize:   256,
		},
		logger,
		store,
		client,
		bundles,
		runtime.NewNativeRuntime(logger, collector),
		collector,
		upgrader,
	)

	if err := app.Run(ctx); err != nil {
		logger.Fatal("agent exited with error", zap.Error(err))
	}
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func resolveAgentVersion(explicitVersion, stateDir string) string {
	if value := strings.TrimSpace(explicitVersion); value != "" {
		return value
	}
	if value, err := readVersionFile(filepath.Join(stateDir, "agent-version")); err == nil && value != "" {
		return value
	}
	return defaultAgentVersion
}

func readVersionFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
