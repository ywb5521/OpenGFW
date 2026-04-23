package bootstrap

import (
	"strings"
	"testing"

	"github.com/apernet/OpenGFW/pkg/models"
)

func TestBuildInstallScriptURL(t *testing.T) {
	url, err := BuildInstallScriptURL("https://master.example.com", "token-123", models.InstallConfig{
		InstallDir:   "/opt/bin",
		StateDir:     "/opt/state",
		ServiceName:  "agent-demo",
		BinaryName:   "opengfw-agent",
		TargetGOOS:   "linux",
		TargetGOARCH: "amd64",
	})
	if err != nil {
		t.Fatalf("build install script url: %v", err)
	}
	if !strings.Contains(url, "/api/v1/bootstrap/scripts/token-123") {
		t.Fatalf("unexpected script url: %s", url)
	}
	if !strings.Contains(url, "masterUrl=https%3A%2F%2Fmaster.example.com") {
		t.Fatalf("expected encoded masterUrl in script url: %s", url)
	}
	if !strings.Contains(url, "goarch=amd64") {
		t.Fatalf("expected goarch in script url: %s", url)
	}
	if !strings.Contains(url, "action=install") {
		t.Fatalf("expected action in script url: %s", url)
	}
}

func TestRenderInstallScript(t *testing.T) {
	script, err := RenderInstallScript(models.BootstrapInstallRequest{
		Name:         "gw-1",
		Hostname:     "gw-1-host",
		ManagementIP: "10.0.0.10",
		AgentVersion: "0.1.0",
		Install: models.InstallConfig{
			MasterURL:   "https://master.example.com",
			InstallDir:  "/usr/local/bin",
			StateDir:    "/var/lib/opengfw-agent",
			ServiceName: "opengfw-agent",
			BinaryName:  "opengfw-agent",
		},
	}, "token-123")
	if err != nil {
		t.Fatalf("render install script: %v", err)
	}
	if !strings.Contains(script, "/api/v1/bootstrap/binaries/${TOKEN}?goos=${GOOS}&goarch=${GOARCH}") {
		t.Fatalf("expected binary download URL in script, got:\n%s", script)
	}
	if !strings.Contains(script, `Environment="OPENGFW_BOOTSTRAP_TOKEN=token-123"`) {
		t.Fatalf("expected bootstrap token in systemd service, got:\n%s", script)
	}
	if !strings.Contains(script, `"--master" "https://master.example.com"`) {
		t.Fatalf("expected master URL in service content, got:\n%s", script)
	}
}

func TestGenerateInstallCommand(t *testing.T) {
	command := GenerateInstallCommand("https://master.example.com/install.sh", true)
	if command != "curl -fsSL 'https://master.example.com/install.sh' | sudo sh" {
		t.Fatalf("unexpected install command: %s", command)
	}
}

func TestBuildUninstallScriptURL(t *testing.T) {
	url, err := BuildUninstallScriptURL("https://master.example.com", "token-123", models.InstallConfig{
		ServiceName: "opengfw-agent",
	})
	if err != nil {
		t.Fatalf("build uninstall script url: %v", err)
	}
	if !strings.Contains(url, "action=uninstall") {
		t.Fatalf("expected uninstall action in script url: %s", url)
	}
}

func TestRenderUninstallScript(t *testing.T) {
	script, err := RenderUninstallScript(models.BootstrapInstallRequest{
		Install: models.InstallConfig{
			InstallDir:  "/usr/local/bin",
			StateDir:    "/var/lib/opengfw-agent",
			ServiceName: "opengfw-agent",
			BinaryName:  "opengfw-agent",
		},
	}, "token-123")
	if err != nil {
		t.Fatalf("render uninstall script: %v", err)
	}
	if !strings.Contains(script, "detect_goos") {
		t.Fatalf("expected platform detection in uninstall script, got:\n%s", script)
	}
	if !strings.Contains(script, "systemctl disable --now") {
		t.Fatalf("expected systemd cleanup in uninstall script, got:\n%s", script)
	}
}
