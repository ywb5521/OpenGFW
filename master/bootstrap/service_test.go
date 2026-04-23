package bootstrap

import (
	"context"
	"strings"
	"testing"

	"github.com/apernet/OpenGFW/master/agentbuild"
	"github.com/apernet/OpenGFW/pkg/models"
)

func TestRenderSystemdService(t *testing.T) {
	unit := string(renderSystemdService(models.BootstrapInstallRequest{
		Name:         "gw-1",
		Hostname:     "gw-1-host",
		ManagementIP: "10.0.0.10",
		AgentVersion: "0.1.0",
		Install: models.InstallConfig{
			MasterURL: "http://master:8080",
		},
	}, "token123", "/usr/local/bin/opengfw-agent", "/var/lib/opengfw-agent", "opengfw-agent"))

	if !strings.Contains(unit, `Environment="OPENGFW_BOOTSTRAP_TOKEN=token123"`) {
		t.Fatalf("expected bootstrap token env, got:\n%s", unit)
	}
	if !strings.Contains(unit, `"--master" "http://master:8080"`) {
		t.Fatalf("expected master URL in ExecStart, got:\n%s", unit)
	}
	if !strings.Contains(unit, `"--management-ip" "10.0.0.10"`) {
		t.Fatalf("expected management IP in ExecStart, got:\n%s", unit)
	}
	if strings.Contains(unit, `"--version" "0.1.0"`) {
		t.Fatalf("expected unit to avoid pinning agent version, got:\n%s", unit)
	}
	if !strings.Contains(unit, "User=root") {
		t.Fatalf("expected unit to run as root, got:\n%s", unit)
	}
	if !strings.Contains(unit, "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW") {
		t.Fatalf("expected nfqueue capabilities in unit, got:\n%s", unit)
	}
	if !strings.Contains(unit, "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW") {
		t.Fatalf("expected capability bounding set in unit, got:\n%s", unit)
	}
}

func TestShellEscape(t *testing.T) {
	got := shellEscape("ab'cd")
	want := `'ab'\''cd'`
	if got != want {
		t.Fatalf("unexpected shell escape: got %s want %s", got, want)
	}
}

func TestBuildAgentBinariesTypedNilBuilderReturnsError(t *testing.T) {
	var builder *agentbuild.Service
	installer := NewSSHInstaller(builder)

	_, err := installer.BuildAgentBinaries(context.Background(), models.AgentBuildRequest{
		Targets: []models.AgentBuildTarget{{
			GOOS:   "linux",
			GOARCH: "amd64",
		}},
	})
	if err == nil {
		t.Fatal("expected nil builder to return an error")
	}
	if !strings.Contains(err.Error(), "managed agent binary builder is not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}
